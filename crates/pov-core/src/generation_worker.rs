use std::{fmt, sync::Arc, time::Duration};

use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;

use crate::{
    job::{
        ClaimResult, GenerationDispatchReceipt, JobFailureKind, JobOutcome, JobQueueError,
        JobQueueRepository,
    },
    loopback_llm::{LoopbackGenerationErrorKind, LoopbackLlmRuntime},
    storage::StoreSet,
};

const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(200);
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(10);
const MAX_DISPATCH_BATCH: usize = 128;

#[derive(Clone)]
pub struct GenerationWorkerSignal {
    notify: Arc<Notify>,
}

impl GenerationWorkerSignal {
    pub fn wake(&self) {
        self.notify.notify_one();
    }
}

impl fmt::Debug for GenerationWorkerSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationWorkerSignal")
            .finish_non_exhaustive()
    }
}

pub struct GenerationWorkerHandle {
    shutdown: CancellationToken,
    task: JoinHandle<()>,
    provider: Arc<LoopbackLlmRuntime>,
}

impl fmt::Debug for GenerationWorkerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationWorkerHandle")
            .finish_non_exhaustive()
    }
}

impl GenerationWorkerHandle {
    pub async fn shutdown(self) -> Result<(), JobQueueError> {
        self.shutdown.cancel();
        self.task.await.map_err(|_| JobQueueError::BackendFailure)?;
        self.provider
            .shutdown()
            .await
            .map_err(|_| JobQueueError::RecoveryRequired)
    }
}

#[must_use]
pub fn spawn_generation_worker(
    stores: Arc<StoreSet>,
    provider: Arc<LoopbackLlmRuntime>,
) -> (GenerationWorkerSignal, GenerationWorkerHandle) {
    let shutdown = CancellationToken::new();
    let notify = Arc::new(Notify::new());
    let signal = GenerationWorkerSignal {
        notify: Arc::clone(&notify),
    };
    let task_shutdown = shutdown.clone();
    let task_provider = Arc::clone(&provider);
    let task = tokio::spawn(async move {
        run_worker(stores, task_provider, task_shutdown, notify).await;
    });
    (
        signal,
        GenerationWorkerHandle {
            shutdown,
            task,
            provider,
        },
    )
}

async fn run_worker(
    stores: Arc<StoreSet>,
    provider: Arc<LoopbackLlmRuntime>,
    shutdown: CancellationToken,
    notify: Arc<Notify>,
) {
    while !shutdown.is_cancelled() {
        let queue = JobQueueRepository::new(&stores.conversation);
        let mut dispatched = 0;
        while dispatched < MAX_DISPATCH_BATCH && !shutdown.is_cancelled() {
            match queue
                .dispatch_next_generation(provider.mode().dispatch_mode())
                .await
            {
                Ok(GenerationDispatchReceipt::Advanced { .. }) => dispatched += 1,
                Ok(GenerationDispatchReceipt::Idle) => break,
                Err(_) => {
                    wait_for_work(&shutdown, &notify).await;
                    break;
                }
            }
        }
        if shutdown.is_cancelled() {
            break;
        }
        if provider.mode().dispatch_mode() == crate::job::GenerationDispatchMode::Disabled {
            wait_for_work(&shutdown, &notify).await;
            continue;
        }
        match queue.dispatcher().claim_next().await {
            Ok(ClaimResult::Leased(lease)) => {
                process_lease(&queue, Arc::clone(&provider), lease, &shutdown).await;
            }
            Ok(ClaimResult::Idle | ClaimResult::RecoveryRequired(_)) | Err(_) => {
                wait_for_work(&shutdown, &notify).await;
            }
        }
        if dispatched == MAX_DISPATCH_BATCH {
            tokio::task::yield_now().await;
        }
    }
}

async fn wait_for_work(shutdown: &CancellationToken, notify: &Notify) {
    tokio::select! {
        () = shutdown.cancelled() => {}
        () = notify.notified() => {}
        () = time::sleep(IDLE_POLL_INTERVAL) => {}
    }
}

async fn process_lease(
    queue: &JobQueueRepository<'_>,
    provider: Arc<LoopbackLlmRuntime>,
    lease: crate::job::JobLease,
    shutdown: &CancellationToken,
) {
    let dispatcher = queue.dispatcher();
    let Ok(mut running) = dispatcher.mark_running(&lease).await else {
        return;
    };
    let Ok(source) = dispatcher.read_generation_source(&running).await else {
        let _ = dispatcher
            .finish(
                &running,
                JobOutcome::PermanentFailure(JobFailureKind::ExecutionFailed),
            )
            .await;
        return;
    };
    let attempt_cancel = CancellationToken::new();
    let generation = provider.generate(&source, &attempt_cancel);
    tokio::pin!(generation);
    let mut cancel_poll = time::interval(CANCEL_POLL_INTERVAL);
    cancel_poll.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut next_renewal = Instant::now() + LEASE_RENEW_INTERVAL;
    let mut shutdown_seen = false;
    let result = loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled(), if !shutdown_seen => {
                shutdown_seen = true;
                attempt_cancel.cancel();
            }
            result = &mut generation => {
                break result;
            }
            _ = cancel_poll.tick() => {
                if dispatcher.cancel_requested(&running).await.unwrap_or(true) {
                    attempt_cancel.cancel();
                }
                if Instant::now() >= next_renewal {
                    match dispatcher.renew(&running).await {
                        Ok(renewed) => running = renewed,
                        Err(_) => attempt_cancel.cancel(),
                    }
                    next_renewal = Instant::now() + LEASE_RENEW_INTERVAL;
                }
            }
        }
    };
    match result {
        Ok(completion) => {
            if dispatcher.cancel_requested(&running).await.unwrap_or(true) {
                let _ = dispatcher.finish(&running, JobOutcome::Cancelled).await;
            } else if dispatcher
                .complete_generation(&running, completion)
                .await
                .is_err()
            {
                let outcome = if dispatcher.cancel_requested(&running).await.unwrap_or(false) {
                    JobOutcome::Cancelled
                } else {
                    JobOutcome::RetryableFailure(JobFailureKind::ExecutionFailed)
                };
                let _ = dispatcher.finish(&running, outcome).await;
            }
        }
        Err(error) => match error.kind() {
            LoopbackGenerationErrorKind::ProviderUnavailable => {
                let _ = dispatcher
                    .finish(
                        &running,
                        JobOutcome::RetryableFailure(JobFailureKind::ProviderUnavailable),
                    )
                    .await;
            }
            LoopbackGenerationErrorKind::Timeout => {
                let _ = dispatcher
                    .finish(
                        &running,
                        JobOutcome::RetryableFailure(JobFailureKind::Timeout),
                    )
                    .await;
            }
            LoopbackGenerationErrorKind::ExecutionFailed => {
                let _ = dispatcher
                    .finish(
                        &running,
                        JobOutcome::RetryableFailure(JobFailureKind::ExecutionFailed),
                    )
                    .await;
            }
            LoopbackGenerationErrorKind::Cancelled => {
                let outcome = if dispatcher.cancel_requested(&running).await.unwrap_or(false) {
                    JobOutcome::Cancelled
                } else {
                    JobOutcome::RetryableFailure(JobFailureKind::ExecutionFailed)
                };
                let _ = dispatcher.finish(&running, outcome).await;
            }
            LoopbackGenerationErrorKind::CleanupUncertain => {
                let _ = dispatcher.mark_cleanup_uncertain(&running).await;
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tempfile::tempdir;

    use crate::{
        conversation::{AppendUserEvent, ConversationId, ConversationRepository, IdempotencyKey},
        identity::VerifiedAuthContext,
        job::{JobFailureKind, JobKind, JobQueueRepository, JobState},
        loopback_llm::LoopbackLlmRuntime,
        storage::StoreSet,
    };

    use super::spawn_generation_worker;

    #[tokio::test]
    async fn unavailable_provider_keeps_capture_and_exhausts_retryable_job() {
        let directory = tempdir().expect("temporary directory");
        let stores = Arc::new(
            StoreSet::open(directory.path().join("stores"))
                .await
                .expect("stores open"),
        );
        let provider = Arc::new(LoopbackLlmRuntime::test_unavailable(
            directory.path().join("runtime").join("llm"),
        ));
        let (signal, worker) = spawn_generation_worker(Arc::clone(&stores), Arc::clone(&provider));
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let receipt = ConversationRepository::new(&stores.conversation)
            .append_user_event(
                &owner,
                AppendUserEvent {
                    conversation_id,
                    expected_revision: None,
                    idempotency_key: IdempotencyKey::new(),
                    content: "capture survives unavailable model".to_owned(),
                },
            )
            .await
            .expect("capture append");
        signal.wake();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let terminal = loop {
            match JobQueueRepository::new(&stores.conversation)
                .read_job_by_source(&owner, receipt.outbox.id(), JobKind::ConversationResponseV1)
                .await
            {
                Ok(job) if job.state().is_terminal() => break job,
                Ok(_) | Err(crate::job::JobQueueError::NotFound) => {}
                Err(error) => panic!("job read failed: {error}"),
            }
            assert!(tokio::time::Instant::now() < deadline, "job did not finish");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(terminal.state(), JobState::Failed);
        assert_eq!(terminal.attempts_started(), 3);
        let attempts = JobQueueRepository::new(&stores.conversation)
            .read_attempts(&owner, terminal.id())
            .await
            .expect("attempt history");
        assert_eq!(attempts.len(), 3);
        assert!(
            attempts
                .iter()
                .all(|attempt| { attempt.failure() == Some(JobFailureKind::ProviderUnavailable) })
        );
        let timeline = ConversationRepository::new(&stores.conversation)
            .read_timeline(&owner, conversation_id)
            .await
            .expect("capture timeline");
        assert_eq!(timeline.events().len(), 1);

        worker.shutdown().await.expect("worker shutdown");
        drop(provider);
        drop(stores);
    }

    #[tokio::test]
    #[ignore = "requires explicitly configured local model artifacts"]
    async fn configured_local_model_completes_authenticated_round_trip() {
        let directory = tempdir().expect("temporary directory");
        let canonical_directory =
            std::fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let stores = Arc::new(
            StoreSet::open(canonical_directory.join("stores"))
                .await
                .expect("stores open"),
        );
        let provider = Arc::new(LoopbackLlmRuntime::from_environment(
            canonical_directory.join("runtime").join("llm"),
        ));
        assert_eq!(
            provider.mode(),
            crate::loopback_llm::LoopbackLlmMode::Ready,
            "the explicit local model environment must be complete and valid"
        );
        let (signal, worker) = spawn_generation_worker(Arc::clone(&stores), Arc::clone(&provider));
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let receipt = ConversationRepository::new(&stores.conversation)
            .append_user_event(
                &owner,
                AppendUserEvent {
                    conversation_id,
                    expected_revision: None,
                    idempotency_key: IdempotencyKey::new(),
                    content: "Reply briefly that the POV-012 loopback round trip is working."
                        .to_owned(),
                },
            )
            .await
            .expect("source append");
        signal.wake();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8 * 60);
        loop {
            match JobQueueRepository::new(&stores.conversation)
                .read_job_by_source(&owner, receipt.outbox.id(), JobKind::ConversationResponseV1)
                .await
            {
                Ok(job) if job.state() == JobState::Succeeded => break,
                Ok(job) if job.state().is_terminal() => {
                    panic!("configured local model job ended as {:?}", job.state())
                }
                Ok(_) | Err(crate::job::JobQueueError::NotFound) => {}
                Err(error) => panic!("job read failed: {error}"),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "configured model round trip timed out"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let timeline = ConversationRepository::new(&stores.conversation)
            .read_timeline(&owner, conversation_id)
            .await
            .expect("terminal timeline");
        assert_eq!(timeline.events().len(), 2);
        let assistant = &timeline.events()[1];
        assert_eq!(
            assistant.kind(),
            crate::conversation::ConversationEventKind::AssistantText
        );
        assert!(!assistant.content().trim().is_empty());
        assert!(!assistant.content().contains("<think>"));
        assert!(!assistant.content().contains("</think>"));
        assert_eq!(
            crate::storage::job_records::test_generation_result_count(
                &stores.conversation,
                owner.clone(),
            )
            .await
            .expect("stored provenance count"),
            1
        );
        assert!(provider.test_unauthenticated_inference_is_rejected().await);

        worker.shutdown().await.expect("clean provider shutdown");
        assert!(provider.test_listener_is_absent().await);
        drop(provider);
        drop(stores);
    }
}
