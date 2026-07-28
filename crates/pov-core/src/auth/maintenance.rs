use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context, Poll},
    thread,
};

use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};

use super::secret_fs::{
    AuthCleanInstanceState, AuthInitializationActiveKeyInstallOutcome,
    AuthInitializationCleanupOutcome, AuthInitializationFinalLifecycleOutcome,
    AuthInitializationPreSourceRecoveryOutcome, AuthInitializationPrepareOutcome,
    AuthInitializationReconciliation, AuthInitializationRollbackOutcome,
    AuthInitializationSourceOutcome, AuthMaintenanceContext,
    AuthPlannedRotationActiveKeyInstallOutcome, AuthPlannedRotationCleanupOutcome,
    AuthPlannedRotationFinalLifecycleOutcome, AuthPlannedRotationPrepareOutcome,
    AuthPlannedRotationReconciliation, AuthPlannedRotationRollbackOutcome,
    AuthPlannedRotationSourceOutcome, AuthRetireActiveKeyInstallOutcome, AuthRetireCleanupOutcome,
    AuthRetireFinalLifecycleOutcome, AuthRetirePrepareOutcome, AuthRetireReconciliation,
    AuthRetireRollbackOutcome, AuthRetireSourceOutcome, AuthStoreBindingError,
    OwnedAuthMaintenanceContext,
};
#[cfg(test)]
use super::secret_fs::{
    AuthInitializationActiveKeyInstallTestFault, AuthInitializationCleanupTestFault,
    AuthInitializationPreSourceRecoveryTestFault, AuthInitializationPrepareTestFault,
    AuthInitializationRollbackTestFault, AuthInitializationSourceDurabilityTestFault,
    AuthPlannedRotationActiveKeyInstallTestFault, AuthPlannedRotationCleanupTestFault,
    AuthPlannedRotationPrepareTestFault, AuthPlannedRotationRollbackTestFault,
    AuthPlannedRotationSourceDurabilityTestFault, AuthRetirePrepareTestFault,
    AuthRetireRollbackTestFault,
};
use super::transition::{
    InitializationPreparationV1, PlannedRotationPreparationV1, RetirePreparationV1,
};
#[cfg(test)]
use crate::storage::{
    AuthInitializationFinalLifecycleMutationTestFault, AuthInitializationSourceMutationTestFault,
    AuthPlannedRotationFinalLifecycleMutationTestFault, AuthPlannedRotationSourceMutationTestFault,
};

const ACTOR_THREAD_NAME: &str = "pov-auth-maintenance";

pub(crate) struct AuthMaintenanceActor {
    sender: Option<mpsc::Sender<MaintenanceCommand>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl AuthMaintenanceActor {
    pub(crate) fn start(
        context: AuthMaintenanceContext<'_>,
    ) -> Result<Self, AuthMaintenanceActorError> {
        let context = context.into_owned()?;
        let (sender, receiver) = mpsc::channel(1);
        let worker = thread::Builder::new()
            .name(ACTOR_THREAD_NAME.to_owned())
            .spawn(move || actor_thread(context, receiver))
            .map_err(|error| AuthMaintenanceActorError::ThreadStart(error.kind()))?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    pub(crate) fn start_revalidation(
        &self,
    ) -> Result<AuthMaintenanceRun<()>, AuthMaintenanceActorError> {
        self.start_revalidation_command(
            #[cfg(test)]
            None,
        )
    }

    fn start_revalidation_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<()>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::Revalidate {
                #[cfg(test)]
                gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn revalidate(&self) -> Result<(), AuthMaintenanceActorError> {
        self.start_revalidation()?.await
    }

    pub(crate) fn start_clean_instance_inspection(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthCleanInstanceState>, AuthMaintenanceActorError> {
        self.start_clean_instance_inspection_command(
            #[cfg(test)]
            None,
        )
    }

    fn start_clean_instance_inspection_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthCleanInstanceState>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InspectCleanInstance {
                #[cfg(test)]
                gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn inspect_clean_instance(
        &self,
    ) -> Result<AuthCleanInstanceState, AuthMaintenanceActorError> {
        self.start_clean_instance_inspection()?.await
    }

    pub(crate) fn start_initialization_reconciliation(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthInitializationReconciliation>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InspectInitializationReconciliation { response })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn inspect_initialization_reconciliation(
        &self,
    ) -> Result<AuthInitializationReconciliation, AuthMaintenanceActorError> {
        self.start_initialization_reconciliation()?.await
    }

    pub(crate) fn start_planned_rotation_reconciliation(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationReconciliation>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InspectPlannedRotationReconciliation { response })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn inspect_planned_rotation_reconciliation(
        &self,
    ) -> Result<AuthPlannedRotationReconciliation, AuthMaintenanceActorError> {
        self.start_planned_rotation_reconciliation()?.await
    }

    pub(crate) fn start_prepare_planned_rotation(
        &self,
        preparation: PlannedRotationPreparationV1,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_planned_rotation_command(
            preparation,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_prepare_planned_rotation_command(
        &self,
        preparation: PlannedRotationPreparationV1,
        #[cfg(test)] fault: Option<AuthPlannedRotationPrepareTestFault>,
        #[cfg(test)] pre_mutation_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationPrepareOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::PreparePlannedRotation {
                preparation: Box::new(preparation),
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn prepare_planned_rotation(
        &self,
        preparation: PlannedRotationPreparationV1,
    ) -> Result<AuthPlannedRotationPrepareOutcome, AuthMaintenanceActorError> {
        self.start_prepare_planned_rotation(preparation)?.await
    }

    pub(crate) fn start_rollback_planned_rotation_pre_source(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_planned_rotation_pre_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_rollback_planned_rotation_pre_source_command(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationRollbackTestFault>,
        #[cfg(test)] before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_first_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_rollback_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationRollbackOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::RollbackPlannedRotationPreSource {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_first_mutation_gate,
                #[cfg(test)]
                after_rollback_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn rollback_planned_rotation_pre_source(
        &self,
    ) -> Result<AuthPlannedRotationRollbackOutcome, AuthMaintenanceActorError> {
        self.start_rollback_planned_rotation_pre_source()?.await
    }

    pub(crate) fn start_retire_reconciliation(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthRetireReconciliation>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InspectRetireReconciliation { response })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn inspect_retire_reconciliation(
        &self,
    ) -> Result<AuthRetireReconciliation, AuthMaintenanceActorError> {
        self.start_retire_reconciliation()?.await
    }

    pub(crate) fn start_prepare_retire(
        &self,
        preparation: RetirePreparationV1,
    ) -> Result<AuthMaintenanceRun<AuthRetirePrepareOutcome>, AuthMaintenanceActorError> {
        self.start_prepare_retire_command(
            preparation,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_prepare_retire_command(
        &self,
        preparation: RetirePreparationV1,
        #[cfg(test)] fault: Option<AuthRetirePrepareTestFault>,
        #[cfg(test)] pre_mutation_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthRetirePrepareOutcome>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::PrepareRetire {
                preparation: Box::new(preparation),
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn prepare_retire(
        &self,
        preparation: RetirePreparationV1,
    ) -> Result<AuthRetirePrepareOutcome, AuthMaintenanceActorError> {
        self.start_prepare_retire(preparation)?.await
    }

    pub(crate) fn start_rollback_retire_pre_source(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthRetireRollbackOutcome>, AuthMaintenanceActorError> {
        self.start_rollback_retire_pre_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_rollback_retire_pre_source_command(
        &self,
        #[cfg(test)] fault: Option<AuthRetireRollbackTestFault>,
        #[cfg(test)] before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_first_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_rollback_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthRetireRollbackOutcome>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::RollbackRetirePreSource {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_first_mutation_gate,
                #[cfg(test)]
                after_rollback_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn rollback_retire_pre_source(
        &self,
    ) -> Result<AuthRetireRollbackOutcome, AuthMaintenanceActorError> {
        self.start_rollback_retire_pre_source()?.await
    }

    pub(crate) fn start_commit_retire_source(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthRetireSourceOutcome>, AuthMaintenanceActorError> {
        self.start_commit_retire_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_commit_retire_source_command(
        &self,
        #[cfg(test)] mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        #[cfg(test)] durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
    ) -> Result<AuthMaintenanceRun<AuthRetireSourceOutcome>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitRetireSource {
                #[cfg(test)]
                mutation_fault,
                #[cfg(test)]
                durability_fault,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn commit_retire_source(
        &self,
    ) -> Result<AuthRetireSourceOutcome, AuthMaintenanceActorError> {
        self.start_commit_retire_source()?.await
    }

    pub(crate) fn start_install_retire_active_key(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthRetireActiveKeyInstallOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InstallRetireActiveKey {
                #[cfg(test)]
                fault: None,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn install_retire_active_key(
        &self,
    ) -> Result<AuthRetireActiveKeyInstallOutcome, AuthMaintenanceActorError> {
        self.start_install_retire_active_key()?.await
    }

    pub(crate) fn start_commit_retire_final_lifecycle(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthRetireFinalLifecycleOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitRetireFinalLifecycle {
                #[cfg(test)]
                fault: None,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn commit_retire_final_lifecycle(
        &self,
    ) -> Result<AuthRetireFinalLifecycleOutcome, AuthMaintenanceActorError> {
        self.start_commit_retire_final_lifecycle()?.await
    }

    pub(crate) fn start_cleanup_retire(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthRetireCleanupOutcome>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CleanupRetire {
                #[cfg(test)]
                fault: None,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn cleanup_retire(
        &self,
    ) -> Result<AuthRetireCleanupOutcome, AuthMaintenanceActorError> {
        self.start_cleanup_retire()?.await
    }

    pub(crate) fn start_commit_planned_rotation_source(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_planned_rotation_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_commit_planned_rotation_source_command(
        &self,
        #[cfg(test)] mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        #[cfg(test)] durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        #[cfg(test)] before_source_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_source_mutation_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationSourceOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitPlannedRotationSource {
                #[cfg(test)]
                mutation_fault,
                #[cfg(test)]
                durability_fault,
                #[cfg(test)]
                before_source_mutation_gate,
                #[cfg(test)]
                after_source_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn commit_planned_rotation_source(
        &self,
    ) -> Result<AuthPlannedRotationSourceOutcome, AuthMaintenanceActorError> {
        self.start_commit_planned_rotation_source()?.await
    }

    pub(crate) fn start_install_planned_rotation_active_key(
        &self,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_planned_rotation_active_key_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_install_planned_rotation_active_key_command(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        #[cfg(test)] before_exchange_gate: Option<ActorTestGate>,
        #[cfg(test)] after_exchange_gate: Option<ActorTestGate>,
        #[cfg(test)] after_old_active_removal_gate: Option<ActorTestGate>,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InstallPlannedRotationActiveKey {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_exchange_gate,
                #[cfg(test)]
                after_exchange_gate,
                #[cfg(test)]
                after_old_active_removal_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn install_planned_rotation_active_key(
        &self,
    ) -> Result<AuthPlannedRotationActiveKeyInstallOutcome, AuthMaintenanceActorError> {
        self.start_install_planned_rotation_active_key()?.await
    }

    pub(crate) fn start_commit_planned_rotation_final_lifecycle(
        &self,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_planned_rotation_final_lifecycle_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_commit_planned_rotation_final_lifecycle_command(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        #[cfg(test)] before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_mutation_gate: Option<ActorTestGate>,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitPlannedRotationFinalLifecycle {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn commit_planned_rotation_final_lifecycle(
        &self,
    ) -> Result<AuthPlannedRotationFinalLifecycleOutcome, AuthMaintenanceActorError> {
        self.start_commit_planned_rotation_final_lifecycle()?.await
    }

    pub(crate) fn start_cleanup_planned_rotation(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_planned_rotation_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_cleanup_planned_rotation_command(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationCleanupTestFault>,
        #[cfg(test)] before_rename_gate: Option<ActorTestGate>,
        #[cfg(test)] after_cleanup_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationCleanupOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CleanupPlannedRotation {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_rename_gate,
                #[cfg(test)]
                after_cleanup_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn cleanup_planned_rotation(
        &self,
    ) -> Result<AuthPlannedRotationCleanupOutcome, AuthMaintenanceActorError> {
        self.start_cleanup_planned_rotation()?.await
    }

    pub(crate) fn start_prepare_initialization(
        &self,
        preparation: InitializationPreparationV1,
    ) -> Result<AuthMaintenanceRun<AuthInitializationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_initialization_command(
            preparation,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_prepare_initialization_command(
        &self,
        preparation: InitializationPreparationV1,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] fault: Option<AuthInitializationPrepareTestFault>,
        #[cfg(test)] pre_mutation_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthInitializationPrepareOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::PrepareInitialization {
                preparation: Box::new(preparation),
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn prepare_initialization(
        &self,
        preparation: InitializationPreparationV1,
    ) -> Result<AuthInitializationPrepareOutcome, AuthMaintenanceActorError> {
        self.start_prepare_initialization(preparation)?.await
    }

    pub(crate) fn start_recover_initialization_pre_source(
        &self,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationPreSourceRecoveryOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_recover_initialization_pre_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_recover_initialization_pre_source_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] fault: Option<AuthInitializationPreSourceRecoveryTestFault>,
        #[cfg(test)] before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_recovery_gate: Option<ActorTestGate>,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationPreSourceRecoveryOutcome>,
        AuthMaintenanceActorError,
    > {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::RecoverInitializationPreSource {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_recovery_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn recover_initialization_pre_source(
        &self,
    ) -> Result<AuthInitializationPreSourceRecoveryOutcome, AuthMaintenanceActorError> {
        self.start_recover_initialization_pre_source()?.await
    }

    pub(crate) fn start_rollback_initialization_pre_source(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthInitializationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_initialization_pre_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_rollback_initialization_pre_source_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] fault: Option<AuthInitializationRollbackTestFault>,
        #[cfg(test)] before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] after_rollback_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthInitializationRollbackOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::RollbackInitializationPreSource {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_rollback_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn rollback_initialization_pre_source(
        &self,
    ) -> Result<AuthInitializationRollbackOutcome, AuthMaintenanceActorError> {
        self.start_rollback_initialization_pre_source()?.await
    }

    pub(crate) fn start_commit_initialization_source(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_initialization_source_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_commit_initialization_source_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] mutation_fault: Option<AuthInitializationSourceMutationTestFault>,
        #[cfg(test)] durability_fault: Option<AuthInitializationSourceDurabilityTestFault>,
        #[cfg(test)] pre_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] post_mutation_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitInitializationSource {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                mutation_fault,
                #[cfg(test)]
                durability_fault,
                #[cfg(test)]
                pre_mutation_gate,
                #[cfg(test)]
                post_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn commit_initialization_source(
        &self,
    ) -> Result<AuthInitializationSourceOutcome, AuthMaintenanceActorError> {
        self.start_commit_initialization_source()?.await
    }

    pub(crate) fn start_install_initialization_active_key(
        &self,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_initialization_active_key_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_install_initialization_active_key_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] fault: Option<AuthInitializationActiveKeyInstallTestFault>,
        #[cfg(test)] before_publish_gate: Option<ActorTestGate>,
        #[cfg(test)] after_publish_gate: Option<ActorTestGate>,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InstallInitializationActiveKey {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_publish_gate,
                #[cfg(test)]
                after_publish_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn install_initialization_active_key(
        &self,
    ) -> Result<AuthInitializationActiveKeyInstallOutcome, AuthMaintenanceActorError> {
        self.start_install_initialization_active_key()?.await
    }

    pub(crate) fn start_commit_initialization_final_lifecycle(
        &self,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_initialization_final_lifecycle_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_commit_initialization_final_lifecycle_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] fault: Option<AuthInitializationFinalLifecycleMutationTestFault>,
        #[cfg(test)] pre_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)] post_mutation_gate: Option<ActorTestGate>,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitInitializationFinalLifecycle {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                #[cfg(test)]
                post_mutation_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn commit_initialization_final_lifecycle(
        &self,
    ) -> Result<AuthInitializationFinalLifecycleOutcome, AuthMaintenanceActorError> {
        self.start_commit_initialization_final_lifecycle()?.await
    }

    pub(crate) fn start_cleanup_initialization(
        &self,
    ) -> Result<AuthMaintenanceRun<AuthInitializationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_initialization_command(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    fn start_cleanup_initialization_command(
        &self,
        #[cfg(test)] gate: Option<ActorTestGate>,
        #[cfg(test)] fault: Option<AuthInitializationCleanupTestFault>,
        #[cfg(test)] before_rename_gate: Option<ActorTestGate>,
        #[cfg(test)] after_cleanup_gate: Option<ActorTestGate>,
    ) -> Result<AuthMaintenanceRun<AuthInitializationCleanupOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CleanupInitialization {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_rename_gate,
                #[cfg(test)]
                after_cleanup_gate,
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    pub(crate) async fn cleanup_initialization(
        &self,
    ) -> Result<AuthInitializationCleanupOutcome, AuthMaintenanceActorError> {
        self.start_cleanup_initialization()?.await
    }

    pub(crate) async fn shutdown(self) -> Result<(), AuthMaintenanceActorError> {
        self.start_shutdown()?.await
    }

    pub(crate) fn start_shutdown(
        self,
    ) -> Result<AuthMaintenanceShutdown, AuthMaintenanceActorError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| AuthMaintenanceActorError::NoRuntime)?;
        let worker = runtime.spawn_blocking(move || self.shutdown_blocking());
        Ok(AuthMaintenanceShutdown { worker })
    }

    fn shutdown_blocking(mut self) -> Result<(), AuthMaintenanceActorError> {
        self.sender
            .take()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        let worker = self
            .worker
            .take()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        let join_result = worker.join();
        if join_result.is_err() {
            return Err(AuthMaintenanceActorError::Unavailable);
        }
        Ok(())
    }

    #[cfg(test)]
    fn start_revalidation_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<()>, AuthMaintenanceActorError> {
        self.start_revalidation_command(Some(gate))
    }

    #[cfg(test)]
    fn start_clean_instance_inspection_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthCleanInstanceState>, AuthMaintenanceActorError> {
        self.start_clean_instance_inspection_command(Some(gate))
    }

    #[cfg(test)]
    fn start_prepare_planned_rotation_with_fault(
        &self,
        preparation: PlannedRotationPreparationV1,
        fault: AuthPlannedRotationPrepareTestFault,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_planned_rotation_command(preparation, Some(fault), None)
    }

    #[cfg(test)]
    fn start_prepare_planned_rotation_with_pre_mutation_gate(
        &self,
        preparation: PlannedRotationPreparationV1,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_planned_rotation_command(preparation, None, Some(gate))
    }

    #[cfg(test)]
    fn start_rollback_planned_rotation_pre_source_with_fault(
        &self,
        fault: AuthPlannedRotationRollbackTestFault,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_planned_rotation_pre_source_command(Some(fault), None, None, None)
    }

    #[cfg(test)]
    fn start_rollback_planned_rotation_pre_source_with_before_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_planned_rotation_pre_source_command(None, Some(gate), None, None)
    }

    #[cfg(test)]
    fn start_rollback_planned_rotation_pre_source_with_after_first_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_planned_rotation_pre_source_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_rollback_planned_rotation_pre_source_with_after_rollback_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_planned_rotation_pre_source_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_prepare_retire_with_fault(
        &self,
        preparation: RetirePreparationV1,
        fault: AuthRetirePrepareTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetirePrepareOutcome>, AuthMaintenanceActorError> {
        self.start_prepare_retire_command(preparation, Some(fault), None)
    }

    #[cfg(test)]
    fn start_prepare_retire_with_pre_mutation_gate(
        &self,
        preparation: RetirePreparationV1,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthRetirePrepareOutcome>, AuthMaintenanceActorError> {
        self.start_prepare_retire_command(preparation, None, Some(gate))
    }

    #[cfg(test)]
    fn start_rollback_retire_pre_source_with_fault(
        &self,
        fault: AuthRetireRollbackTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetireRollbackOutcome>, AuthMaintenanceActorError> {
        self.start_rollback_retire_pre_source_command(Some(fault), None, None, None)
    }

    #[cfg(test)]
    fn start_rollback_retire_pre_source_with_before_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthRetireRollbackOutcome>, AuthMaintenanceActorError> {
        self.start_rollback_retire_pre_source_command(None, Some(gate), None, None)
    }

    #[cfg(test)]
    fn start_rollback_retire_pre_source_with_after_first_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthRetireRollbackOutcome>, AuthMaintenanceActorError> {
        self.start_rollback_retire_pre_source_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_rollback_retire_pre_source_with_after_rollback_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthRetireRollbackOutcome>, AuthMaintenanceActorError> {
        self.start_rollback_retire_pre_source_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_commit_retire_source_with_fault(
        &self,
        fault: AuthPlannedRotationSourceMutationTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetireSourceOutcome>, AuthMaintenanceActorError> {
        self.start_commit_retire_source_command(Some(fault), None)
    }

    #[cfg(test)]
    fn start_commit_retire_source_with_durability_fault(
        &self,
        fault: AuthPlannedRotationSourceDurabilityTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetireSourceOutcome>, AuthMaintenanceActorError> {
        self.start_commit_retire_source_command(None, Some(fault))
    }

    #[cfg(test)]
    fn start_install_retire_active_key_with_fault(
        &self,
        fault: AuthPlannedRotationActiveKeyInstallTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetireActiveKeyInstallOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::InstallRetireActiveKey {
                fault: Some(fault),
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    #[cfg(test)]
    fn start_commit_retire_final_lifecycle_with_fault(
        &self,
        fault: AuthPlannedRotationFinalLifecycleMutationTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetireFinalLifecycleOutcome>, AuthMaintenanceActorError>
    {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CommitRetireFinalLifecycle {
                fault: Some(fault),
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    #[cfg(test)]
    fn start_cleanup_retire_with_fault(
        &self,
        fault: AuthPlannedRotationCleanupTestFault,
    ) -> Result<AuthMaintenanceRun<AuthRetireCleanupOutcome>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::CleanupRetire {
                fault: Some(fault),
                response,
            })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_source_with_fault(
        &self,
        fault: AuthPlannedRotationSourceMutationTestFault,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_planned_rotation_source_command(Some(fault), None, None, None)
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_source_with_durability_fault(
        &self,
        fault: AuthPlannedRotationSourceDurabilityTestFault,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_planned_rotation_source_command(None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_source_with_pre_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_planned_rotation_source_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_source_with_post_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_planned_rotation_source_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_install_planned_rotation_active_key_with_fault(
        &self,
        fault: AuthPlannedRotationActiveKeyInstallTestFault,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_planned_rotation_active_key_command(Some(fault), None, None, None)
    }

    #[cfg(test)]
    fn start_install_planned_rotation_active_key_with_before_exchange_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_planned_rotation_active_key_command(None, Some(gate), None, None)
    }

    #[cfg(test)]
    fn start_install_planned_rotation_active_key_with_after_exchange_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_planned_rotation_active_key_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_install_planned_rotation_active_key_with_after_old_active_removal_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_planned_rotation_active_key_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_final_lifecycle_with_fault(
        &self,
        fault: AuthPlannedRotationFinalLifecycleMutationTestFault,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_planned_rotation_final_lifecycle_command(Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_final_lifecycle_with_before_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_planned_rotation_final_lifecycle_command(None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_commit_planned_rotation_final_lifecycle_with_after_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthPlannedRotationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_planned_rotation_final_lifecycle_command(None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_cleanup_planned_rotation_with_fault(
        &self,
        fault: AuthPlannedRotationCleanupTestFault,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_planned_rotation_command(Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_cleanup_planned_rotation_with_before_rename_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_planned_rotation_command(None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_cleanup_planned_rotation_with_after_cleanup_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthPlannedRotationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_planned_rotation_command(None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_prepare_initialization_with_gate(
        &self,
        preparation: InitializationPreparationV1,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_initialization_command(preparation, Some(gate), None, None)
    }

    #[cfg(test)]
    fn start_prepare_initialization_with_fault(
        &self,
        preparation: InitializationPreparationV1,
        fault: AuthInitializationPrepareTestFault,
    ) -> Result<AuthMaintenanceRun<AuthInitializationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_initialization_command(preparation, None, Some(fault), None)
    }

    #[cfg(test)]
    fn start_prepare_initialization_with_pre_mutation_gate(
        &self,
        preparation: InitializationPreparationV1,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationPrepareOutcome>, AuthMaintenanceActorError>
    {
        self.start_prepare_initialization_command(preparation, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_recover_initialization_pre_source_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationPreSourceRecoveryOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_recover_initialization_pre_source_command(Some(gate), None, None, None)
    }

    #[cfg(test)]
    fn start_recover_initialization_pre_source_with_fault(
        &self,
        fault: AuthInitializationPreSourceRecoveryTestFault,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationPreSourceRecoveryOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_recover_initialization_pre_source_command(None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_recover_initialization_pre_source_with_before_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationPreSourceRecoveryOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_recover_initialization_pre_source_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_recover_initialization_pre_source_with_after_recovery_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationPreSourceRecoveryOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_recover_initialization_pre_source_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_rollback_initialization_pre_source_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_initialization_pre_source_command(Some(gate), None, None, None)
    }

    #[cfg(test)]
    fn start_rollback_initialization_pre_source_with_fault(
        &self,
        fault: AuthInitializationRollbackTestFault,
    ) -> Result<AuthMaintenanceRun<AuthInitializationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_initialization_pre_source_command(None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_rollback_initialization_pre_source_with_before_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_initialization_pre_source_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_rollback_initialization_pre_source_with_after_rollback_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationRollbackOutcome>, AuthMaintenanceActorError>
    {
        self.start_rollback_initialization_pre_source_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_commit_initialization_source_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_initialization_source_command(Some(gate), None, None, None, None)
    }

    #[cfg(test)]
    fn start_commit_initialization_source_with_fault(
        &self,
        fault: AuthInitializationSourceMutationTestFault,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_initialization_source_command(None, Some(fault), None, None, None)
    }

    #[cfg(test)]
    fn start_commit_initialization_source_with_durability_fault(
        &self,
        fault: AuthInitializationSourceDurabilityTestFault,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_initialization_source_command(None, None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_commit_initialization_source_with_pre_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_initialization_source_command(None, None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_commit_initialization_source_with_post_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationSourceOutcome>, AuthMaintenanceActorError>
    {
        self.start_commit_initialization_source_command(None, None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_install_initialization_active_key_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_initialization_active_key_command(Some(gate), None, None, None)
    }

    #[cfg(test)]
    fn start_install_initialization_active_key_with_fault(
        &self,
        fault: AuthInitializationActiveKeyInstallTestFault,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_initialization_active_key_command(None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_install_initialization_active_key_with_before_publish_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_initialization_active_key_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_install_initialization_active_key_with_after_publish_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationActiveKeyInstallOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_install_initialization_active_key_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_commit_initialization_final_lifecycle_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_initialization_final_lifecycle_command(Some(gate), None, None, None)
    }

    #[cfg(test)]
    fn start_commit_initialization_final_lifecycle_with_fault(
        &self,
        fault: AuthInitializationFinalLifecycleMutationTestFault,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_initialization_final_lifecycle_command(None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_commit_initialization_final_lifecycle_with_pre_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_initialization_final_lifecycle_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_commit_initialization_final_lifecycle_with_post_mutation_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<
        AuthMaintenanceRun<AuthInitializationFinalLifecycleOutcome>,
        AuthMaintenanceActorError,
    > {
        self.start_commit_initialization_final_lifecycle_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_cleanup_initialization_with_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_initialization_command(Some(gate), None, None, None)
    }

    #[cfg(test)]
    fn start_cleanup_initialization_with_fault(
        &self,
        fault: AuthInitializationCleanupTestFault,
    ) -> Result<AuthMaintenanceRun<AuthInitializationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_initialization_command(None, Some(fault), None, None)
    }

    #[cfg(test)]
    fn start_cleanup_initialization_with_before_rename_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_initialization_command(None, None, Some(gate), None)
    }

    #[cfg(test)]
    fn start_cleanup_initialization_with_after_cleanup_gate(
        &self,
        gate: ActorTestGate,
    ) -> Result<AuthMaintenanceRun<AuthInitializationCleanupOutcome>, AuthMaintenanceActorError>
    {
        self.start_cleanup_initialization_command(None, None, None, Some(gate))
    }

    #[cfg(test)]
    fn start_panic(&self) -> Result<AuthMaintenanceRun<()>, AuthMaintenanceActorError> {
        let (response, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or(AuthMaintenanceActorError::Unavailable)?;
        sender
            .try_send(MaintenanceCommand::Panic { response })
            .map_err(map_send_error)?;
        Ok(AuthMaintenanceRun { receiver })
    }
}

impl Drop for AuthMaintenanceActor {
    fn drop(&mut self) {
        self.sender.take();
        self.worker.take();
    }
}

impl fmt::Debug for AuthMaintenanceActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthMaintenanceActor")
            .field(&"[DETACHED]")
            .finish()
    }
}

pub(crate) struct AuthMaintenanceRun<T> {
    receiver: oneshot::Receiver<Result<T, AuthMaintenanceActorError>>,
}

impl<T> Future for AuthMaintenanceRun<T> {
    type Output = Result<T, AuthMaintenanceActorError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(AuthMaintenanceActorError::Unavailable)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> fmt::Debug for AuthMaintenanceRun<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthMaintenanceRun")
            .field(&"[PENDING]")
            .finish()
    }
}

pub(crate) struct AuthMaintenanceShutdown {
    worker: tokio::task::JoinHandle<Result<(), AuthMaintenanceActorError>>,
}

impl Future for AuthMaintenanceShutdown {
    type Output = Result<(), AuthMaintenanceActorError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.worker).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(AuthMaintenanceActorError::Unavailable)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl fmt::Debug for AuthMaintenanceShutdown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthMaintenanceShutdown")
            .field(&"[PENDING]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthMaintenanceActorError {
    Binding(AuthStoreBindingError),
    ThreadStart(io::ErrorKind),
    Busy,
    NoRuntime,
    OperationFailed,
    Poisoned,
    Unavailable,
}

impl From<AuthStoreBindingError> for AuthMaintenanceActorError {
    fn from(error: AuthStoreBindingError) -> Self {
        Self::Binding(error)
    }
}

impl fmt::Display for AuthMaintenanceActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Binding(_) => "authentication maintenance binding failed",
            Self::ThreadStart(_) => "authentication maintenance worker could not start",
            Self::Busy => "authentication maintenance worker is busy",
            Self::NoRuntime => "authentication maintenance shutdown requires a runtime",
            Self::OperationFailed => "authentication maintenance operation failed",
            Self::Poisoned => "authentication maintenance worker is poisoned",
            Self::Unavailable => "authentication maintenance worker is unavailable",
        })
    }
}

impl Error for AuthMaintenanceActorError {}

enum MaintenanceCommand {
    Revalidate {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        response: oneshot::Sender<Result<(), AuthMaintenanceActorError>>,
    },
    InspectCleanInstance {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        response: oneshot::Sender<Result<AuthCleanInstanceState, AuthMaintenanceActorError>>,
    },
    InspectInitializationReconciliation {
        response:
            oneshot::Sender<Result<AuthInitializationReconciliation, AuthMaintenanceActorError>>,
    },
    InspectPlannedRotationReconciliation {
        response:
            oneshot::Sender<Result<AuthPlannedRotationReconciliation, AuthMaintenanceActorError>>,
    },
    PreparePlannedRotation {
        preparation: Box<PlannedRotationPreparationV1>,
        #[cfg(test)]
        fault: Option<AuthPlannedRotationPrepareTestFault>,
        #[cfg(test)]
        pre_mutation_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthPlannedRotationPrepareOutcome, AuthMaintenanceActorError>>,
    },
    RollbackPlannedRotationPreSource {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationRollbackTestFault>,
        #[cfg(test)]
        before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_first_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_rollback_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthPlannedRotationRollbackOutcome, AuthMaintenanceActorError>>,
    },
    InspectRetireReconciliation {
        response: oneshot::Sender<Result<AuthRetireReconciliation, AuthMaintenanceActorError>>,
    },
    PrepareRetire {
        preparation: Box<RetirePreparationV1>,
        #[cfg(test)]
        fault: Option<AuthRetirePrepareTestFault>,
        #[cfg(test)]
        pre_mutation_gate: Option<ActorTestGate>,
        response: oneshot::Sender<Result<AuthRetirePrepareOutcome, AuthMaintenanceActorError>>,
    },
    RollbackRetirePreSource {
        #[cfg(test)]
        fault: Option<AuthRetireRollbackTestFault>,
        #[cfg(test)]
        before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_first_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_rollback_gate: Option<ActorTestGate>,
        response: oneshot::Sender<Result<AuthRetireRollbackOutcome, AuthMaintenanceActorError>>,
    },
    CommitRetireSource {
        #[cfg(test)]
        mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        #[cfg(test)]
        durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        response: oneshot::Sender<Result<AuthRetireSourceOutcome, AuthMaintenanceActorError>>,
    },
    InstallRetireActiveKey {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        response:
            oneshot::Sender<Result<AuthRetireActiveKeyInstallOutcome, AuthMaintenanceActorError>>,
    },
    CommitRetireFinalLifecycle {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        response:
            oneshot::Sender<Result<AuthRetireFinalLifecycleOutcome, AuthMaintenanceActorError>>,
    },
    CleanupRetire {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationCleanupTestFault>,
        response: oneshot::Sender<Result<AuthRetireCleanupOutcome, AuthMaintenanceActorError>>,
    },
    CommitPlannedRotationSource {
        #[cfg(test)]
        mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        #[cfg(test)]
        durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        #[cfg(test)]
        before_source_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_source_mutation_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthPlannedRotationSourceOutcome, AuthMaintenanceActorError>>,
    },
    InstallPlannedRotationActiveKey {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        #[cfg(test)]
        before_exchange_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_exchange_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_old_active_removal_gate: Option<ActorTestGate>,
        response: oneshot::Sender<
            Result<AuthPlannedRotationActiveKeyInstallOutcome, AuthMaintenanceActorError>,
        >,
    },
    CommitPlannedRotationFinalLifecycle {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        #[cfg(test)]
        before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_mutation_gate: Option<ActorTestGate>,
        response: oneshot::Sender<
            Result<AuthPlannedRotationFinalLifecycleOutcome, AuthMaintenanceActorError>,
        >,
    },
    CleanupPlannedRotation {
        #[cfg(test)]
        fault: Option<AuthPlannedRotationCleanupTestFault>,
        #[cfg(test)]
        before_rename_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_cleanup_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthPlannedRotationCleanupOutcome, AuthMaintenanceActorError>>,
    },
    PrepareInitialization {
        preparation: Box<InitializationPreparationV1>,
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        fault: Option<AuthInitializationPrepareTestFault>,
        #[cfg(test)]
        pre_mutation_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthInitializationPrepareOutcome, AuthMaintenanceActorError>>,
    },
    RecoverInitializationPreSource {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        fault: Option<AuthInitializationPreSourceRecoveryTestFault>,
        #[cfg(test)]
        before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_recovery_gate: Option<ActorTestGate>,
        response: oneshot::Sender<
            Result<AuthInitializationPreSourceRecoveryOutcome, AuthMaintenanceActorError>,
        >,
    },
    RollbackInitializationPreSource {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        fault: Option<AuthInitializationRollbackTestFault>,
        #[cfg(test)]
        before_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_rollback_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthInitializationRollbackOutcome, AuthMaintenanceActorError>>,
    },
    CommitInitializationSource {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        mutation_fault: Option<AuthInitializationSourceMutationTestFault>,
        #[cfg(test)]
        durability_fault: Option<AuthInitializationSourceDurabilityTestFault>,
        #[cfg(test)]
        pre_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        post_mutation_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthInitializationSourceOutcome, AuthMaintenanceActorError>>,
    },
    InstallInitializationActiveKey {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        fault: Option<AuthInitializationActiveKeyInstallTestFault>,
        #[cfg(test)]
        before_publish_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_publish_gate: Option<ActorTestGate>,
        response: oneshot::Sender<
            Result<AuthInitializationActiveKeyInstallOutcome, AuthMaintenanceActorError>,
        >,
    },
    CommitInitializationFinalLifecycle {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        fault: Option<AuthInitializationFinalLifecycleMutationTestFault>,
        #[cfg(test)]
        pre_mutation_gate: Option<ActorTestGate>,
        #[cfg(test)]
        post_mutation_gate: Option<ActorTestGate>,
        response: oneshot::Sender<
            Result<AuthInitializationFinalLifecycleOutcome, AuthMaintenanceActorError>,
        >,
    },
    CleanupInitialization {
        #[cfg(test)]
        gate: Option<ActorTestGate>,
        #[cfg(test)]
        fault: Option<AuthInitializationCleanupTestFault>,
        #[cfg(test)]
        before_rename_gate: Option<ActorTestGate>,
        #[cfg(test)]
        after_cleanup_gate: Option<ActorTestGate>,
        response:
            oneshot::Sender<Result<AuthInitializationCleanupOutcome, AuthMaintenanceActorError>>,
    },
    #[cfg(test)]
    Panic {
        response: oneshot::Sender<Result<(), AuthMaintenanceActorError>>,
    },
}

impl MaintenanceCommand {
    fn respond_poisoned(self) {
        match self {
            Self::Revalidate { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InspectCleanInstance { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InspectInitializationReconciliation { response } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InspectPlannedRotationReconciliation { response } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::PreparePlannedRotation { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::RollbackPlannedRotationPreSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InspectRetireReconciliation { response } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::PrepareRetire { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::RollbackRetirePreSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CommitRetireSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InstallRetireActiveKey { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CommitRetireFinalLifecycle { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CleanupRetire { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CommitPlannedRotationSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InstallPlannedRotationActiveKey { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CommitPlannedRotationFinalLifecycle { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CleanupPlannedRotation { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::PrepareInitialization { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::RecoverInitializationPreSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::RollbackInitializationPreSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CommitInitializationSource { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::InstallInitializationActiveKey { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CommitInitializationFinalLifecycle { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            Self::CleanupInitialization { response, .. } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
            #[cfg(test)]
            Self::Panic { response } => {
                let _ = response.send(Err(AuthMaintenanceActorError::Poisoned));
            }
        }
    }
}

fn actor_thread(
    context: OwnedAuthMaintenanceContext,
    mut receiver: mpsc::Receiver<MaintenanceCommand>,
) {
    let mut integrity = ActorIntegrityGuard::new(context.poison_handle());
    let mut poisoned = false;
    while let Some(command) = receiver.blocking_recv() {
        if poisoned {
            command.respond_poisoned();
            continue;
        }

        // Future mutation commands must complete synchronously on this exact OS thread so
        // the maintenance lock and store binding cannot be dropped ahead of their work.
        // Expected domain rejections belong in a typed successful response; command errors
        // are reserved for integrity failures and therefore poison the shared store.
        match command {
            MaintenanceCommand::Revalidate {
                #[cfg(test)]
                gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    execute_revalidation(
                        &context,
                        #[cfg(test)]
                        gate,
                    )
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InspectCleanInstance {
                #[cfg(test)]
                gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    execute_clean_inspection(
                        &context,
                        #[cfg(test)]
                        gate,
                    )
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InspectInitializationReconciliation { response } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    context.inspect_initialization_reconciliation()
                })) {
                    Ok(result) => result.map_err(AuthMaintenanceActorError::Binding),
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InspectPlannedRotationReconciliation { response } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    context.inspect_planned_rotation_reconciliation()
                })) {
                    Ok(result) => result.map_err(AuthMaintenanceActorError::Binding),
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::PreparePlannedRotation {
                preparation,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (fault, pre_mutation_gate) {
                        (None, None) => context.prepare_planned_rotation(&preparation),
                        (fault, gate) => context.prepare_planned_rotation_with_test_control(
                            &preparation,
                            fault,
                            move || {
                                if let Some(gate) = gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.prepare_planned_rotation(&preparation);
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::RollbackPlannedRotationPreSource {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_first_mutation_gate,
                #[cfg(test)]
                after_rollback_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (
                        fault,
                        before_mutation_gate,
                        after_first_mutation_gate,
                        after_rollback_gate,
                    ) {
                        (None, None, None, None) => context.rollback_planned_rotation_pre_source(),
                        (
                            fault,
                            before_mutation_gate,
                            after_first_mutation_gate,
                            after_rollback_gate,
                        ) => context.rollback_planned_rotation_pre_source_with_test_control(
                            fault,
                            move || {
                                if let Some(gate) = before_mutation_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_first_mutation_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_rollback_gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.rollback_planned_rotation_pre_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InspectRetireReconciliation { response } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    context.inspect_retire_reconciliation()
                })) {
                    Ok(result) => result.map_err(AuthMaintenanceActorError::Binding),
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::PrepareRetire {
                preparation,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (fault, pre_mutation_gate) {
                        (None, None) => context.prepare_retire(&preparation),
                        (fault, gate) => context.prepare_retire_with_test_control(
                            &preparation,
                            fault,
                            move || {
                                if let Some(gate) = gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.prepare_retire(&preparation);
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::RollbackRetirePreSource {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_first_mutation_gate,
                #[cfg(test)]
                after_rollback_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (
                        fault,
                        before_mutation_gate,
                        after_first_mutation_gate,
                        after_rollback_gate,
                    ) {
                        (None, None, None, None) => context.rollback_retire_pre_source(),
                        (
                            fault,
                            before_mutation_gate,
                            after_first_mutation_gate,
                            after_rollback_gate,
                        ) => context.rollback_retire_pre_source_with_test_control(
                            fault,
                            move || {
                                if let Some(gate) = before_mutation_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_first_mutation_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_rollback_gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.rollback_retire_pre_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CommitRetireSource {
                #[cfg(test)]
                mutation_fault,
                #[cfg(test)]
                durability_fault,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (mutation_fault, durability_fault) {
                        (None, None) => context.commit_retire_source(),
                        (mutation_fault, durability_fault) => context
                            .commit_retire_source_with_test_control(
                                mutation_fault,
                                durability_fault,
                                || {},
                                || {},
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.commit_retire_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InstallRetireActiveKey {
                #[cfg(test)]
                fault,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match fault {
                        None => context.install_retire_active_key(),
                        Some(fault) => context.install_retire_active_key_with_test_control(
                            Some(fault),
                            || {},
                            || {},
                            || {},
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.install_retire_active_key();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CommitRetireFinalLifecycle {
                #[cfg(test)]
                fault,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match fault {
                        None => context.commit_retire_final_lifecycle(),
                        Some(fault) => context.commit_retire_final_lifecycle_with_test_control(
                            Some(fault),
                            || {},
                            || {},
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.commit_retire_final_lifecycle();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CleanupRetire {
                #[cfg(test)]
                fault,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match fault {
                        None => context.cleanup_retire(),
                        Some(fault) => {
                            context.cleanup_retire_with_test_control(Some(fault), || {}, || {})
                        }
                    };
                    #[cfg(not(test))]
                    let result = context.cleanup_retire();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CommitPlannedRotationSource {
                #[cfg(test)]
                mutation_fault,
                #[cfg(test)]
                durability_fault,
                #[cfg(test)]
                before_source_mutation_gate,
                #[cfg(test)]
                after_source_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (
                        mutation_fault,
                        durability_fault,
                        before_source_mutation_gate,
                        after_source_mutation_gate,
                    ) {
                        (None, None, None, None) => context.commit_planned_rotation_source(),
                        (
                            mutation_fault,
                            durability_fault,
                            before_source_mutation_gate,
                            after_source_mutation_gate,
                        ) => context.commit_planned_rotation_source_with_test_control(
                            mutation_fault,
                            durability_fault,
                            move || {
                                if let Some(gate) = before_source_mutation_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_source_mutation_gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.commit_planned_rotation_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InstallPlannedRotationActiveKey {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_exchange_gate,
                #[cfg(test)]
                after_exchange_gate,
                #[cfg(test)]
                after_old_active_removal_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (
                        fault,
                        before_exchange_gate,
                        after_exchange_gate,
                        after_old_active_removal_gate,
                    ) {
                        (None, None, None, None) => context.install_planned_rotation_active_key(),
                        (
                            fault,
                            before_exchange_gate,
                            after_exchange_gate,
                            after_old_active_removal_gate,
                        ) => context.install_planned_rotation_active_key_with_test_control(
                            fault,
                            move || {
                                if let Some(gate) = before_exchange_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_exchange_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = after_old_active_removal_gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.install_planned_rotation_active_key();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CommitPlannedRotationFinalLifecycle {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (fault, before_mutation_gate, after_mutation_gate) {
                        (None, None, None) => context.commit_planned_rotation_final_lifecycle(),
                        (fault, before_mutation_gate, after_mutation_gate) => context
                            .commit_planned_rotation_final_lifecycle_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = before_mutation_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = after_mutation_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.commit_planned_rotation_final_lifecycle();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CleanupPlannedRotation {
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_rename_gate,
                #[cfg(test)]
                after_cleanup_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let result = match (fault, before_rename_gate, after_cleanup_gate) {
                        (None, None, None) => context.cleanup_planned_rotation(),
                        (fault, before_rename_gate, after_cleanup_gate) => context
                            .cleanup_planned_rotation_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = before_rename_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = after_cleanup_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.cleanup_planned_rotation();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::PrepareInitialization {
                preparation,
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (fault, pre_mutation_gate) {
                        (None, None) => context.prepare_initialization(&preparation),
                        (fault, gate) => context.prepare_initialization_with_test_control(
                            &preparation,
                            fault,
                            move || {
                                if let Some(gate) = gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.prepare_initialization(&preparation);
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::RecoverInitializationPreSource {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_recovery_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (fault, before_mutation_gate, after_recovery_gate) {
                        (None, None, None) => context.recover_initialization_pre_source(),
                        (fault, before_mutation_gate, after_recovery_gate) => context
                            .recover_initialization_pre_source_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = before_mutation_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = after_recovery_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.recover_initialization_pre_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::RollbackInitializationPreSource {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_mutation_gate,
                #[cfg(test)]
                after_rollback_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (fault, before_mutation_gate, after_rollback_gate) {
                        (None, None, None) => context.rollback_initialization_pre_source(),
                        (fault, before_mutation_gate, after_rollback_gate) => context
                            .rollback_initialization_pre_source_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = before_mutation_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = after_rollback_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.rollback_initialization_pre_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CommitInitializationSource {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                mutation_fault,
                #[cfg(test)]
                durability_fault,
                #[cfg(test)]
                pre_mutation_gate,
                #[cfg(test)]
                post_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (
                        mutation_fault,
                        durability_fault,
                        pre_mutation_gate,
                        post_mutation_gate,
                    ) {
                        (None, None, None, None) => context.commit_initialization_source(),
                        (
                            mutation_fault,
                            durability_fault,
                            pre_mutation_gate,
                            post_mutation_gate,
                        ) => context.commit_initialization_source_with_test_control(
                            mutation_fault,
                            durability_fault,
                            move || {
                                if let Some(gate) = pre_mutation_gate {
                                    gate.pause();
                                }
                            },
                            move || {
                                if let Some(gate) = post_mutation_gate {
                                    gate.pause();
                                }
                            },
                        ),
                    };
                    #[cfg(not(test))]
                    let result = context.commit_initialization_source();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::InstallInitializationActiveKey {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_publish_gate,
                #[cfg(test)]
                after_publish_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (fault, before_publish_gate, after_publish_gate) {
                        (None, None, None) => context.install_initialization_active_key(),
                        (fault, before_publish_gate, after_publish_gate) => context
                            .install_initialization_active_key_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = before_publish_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = after_publish_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.install_initialization_active_key();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CommitInitializationFinalLifecycle {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                pre_mutation_gate,
                #[cfg(test)]
                post_mutation_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (fault, pre_mutation_gate, post_mutation_gate) {
                        (None, None, None) => context.commit_initialization_final_lifecycle(),
                        (fault, pre_mutation_gate, post_mutation_gate) => context
                            .commit_initialization_final_lifecycle_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = pre_mutation_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = post_mutation_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.commit_initialization_final_lifecycle();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            MaintenanceCommand::CleanupInitialization {
                #[cfg(test)]
                gate,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                before_rename_gate,
                #[cfg(test)]
                after_cleanup_gate,
                response,
            } => {
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(gate) = gate {
                        gate.pause();
                    }
                    #[cfg(test)]
                    let result = match (fault, before_rename_gate, after_cleanup_gate) {
                        (None, None, None) => context.cleanup_initialization(),
                        (fault, before_rename_gate, after_cleanup_gate) => context
                            .cleanup_initialization_with_test_control(
                                fault,
                                move || {
                                    if let Some(gate) = before_rename_gate {
                                        gate.pause();
                                    }
                                },
                                move || {
                                    if let Some(gate) = after_cleanup_gate {
                                        gate.pause();
                                    }
                                },
                            ),
                    };
                    #[cfg(not(test))]
                    let result = context.cleanup_initialization();
                    result.map_err(AuthMaintenanceActorError::Binding)
                })) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
            #[cfg(test)]
            MaintenanceCommand::Panic { response } => {
                let result = match catch_unwind(AssertUnwindSafe(execute_panic)) {
                    Ok(result) => result,
                    Err(_) => Err(AuthMaintenanceActorError::OperationFailed),
                };
                update_actor_integrity(&context, &mut poisoned, &result);
                let _ = response.send(result);
            }
        }
    }
    integrity.disarm();
}

fn update_actor_integrity<T>(
    context: &OwnedAuthMaintenanceContext,
    poisoned: &mut bool,
    result: &Result<T, AuthMaintenanceActorError>,
) {
    if result.is_err() {
        context.poison();
        *poisoned = true;
    }
}

fn execute_revalidation(
    context: &OwnedAuthMaintenanceContext,
    #[cfg(test)] gate: Option<ActorTestGate>,
) -> Result<(), AuthMaintenanceActorError> {
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.pause();
    }
    context
        .revalidate()
        .map_err(AuthMaintenanceActorError::Binding)
}

fn execute_clean_inspection(
    context: &OwnedAuthMaintenanceContext,
    #[cfg(test)] gate: Option<ActorTestGate>,
) -> Result<AuthCleanInstanceState, AuthMaintenanceActorError> {
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.pause();
    }
    context
        .inspect_clean_instance()
        .map_err(AuthMaintenanceActorError::Binding)
}

#[cfg(test)]
fn execute_panic() -> Result<(), AuthMaintenanceActorError> {
    panic!("synthetic authentication maintenance actor panic");
}

struct ActorIntegrityGuard {
    store: crate::storage::AuthStorePoisonHandle,
    armed: bool,
}

impl ActorIntegrityGuard {
    fn new(store: crate::storage::AuthStorePoisonHandle) -> Self {
        Self { store, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

fn map_send_error(error: TrySendError<MaintenanceCommand>) -> AuthMaintenanceActorError {
    match error {
        TrySendError::Full(_) => AuthMaintenanceActorError::Busy,
        TrySendError::Closed(_) => AuthMaintenanceActorError::Unavailable,
    }
}

impl Drop for ActorIntegrityGuard {
    fn drop(&mut self) {
        if self.armed {
            self.store.poison();
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct ActorTestGate {
    reached: std::sync::Arc<std::sync::Barrier>,
    resume: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
impl ActorTestGate {
    fn new() -> Self {
        Self {
            reached: std::sync::Arc::new(std::sync::Barrier::new(2)),
            resume: std::sync::Arc::new(std::sync::Barrier::new(2)),
        }
    }

    fn pause(&self) {
        self.reached.wait();
        self.resume.wait();
    }

    fn wait_until_reached(&self) {
        self.reached.wait();
    }

    fn resume(&self) {
        self.resume.wait();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs, io,
        os::unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, PermissionsExt, symlink},
        },
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use base64ct::{Base64Unpadded, Encoding};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    use tokio_rusqlite::rusqlite::{Connection as RawConnection, params};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use crate::{
        auth::{
            SecretBytes, ValidatedVerifier,
            keyring::{AuthTimestampMicros, Keyring},
            transition::{
                AuditId, AuthOwnerId, InitializationMetadataInput, InitializationMetadataV1,
                InitializationPreparationV1, LoginId, NO_BLOCKLIST_CHECK_SENTINEL,
                PlannedRotationMetadataInput, PlannedRotationPreparationV1, RetireMetadataInput,
                RetirePreparationV1, SourceTimestampMicros, TransitionContractError, TransitionId,
            },
        },
        storage::{
            AuthInitializationFinalLifecycleMutationTestFault,
            AuthInitializationSourceMutationTestFault,
            AuthPlannedRotationFinalLifecycleMutationTestFault,
            AuthPlannedRotationSourceMutationTestFault, StoreError, StoreKind, StoreSet,
        },
    };

    use super::{
        ActorTestGate, AuthMaintenanceActor, AuthMaintenanceActorError, AuthStoreBindingError,
        OwnedAuthMaintenanceContext,
    };
    use crate::auth::secret_fs::{
        AuthCleanInstanceState, AuthInitializationActiveKeyInstallOutcome,
        AuthInitializationActiveKeyInstallTestFault, AuthInitializationBlocker,
        AuthInitializationCleanupOutcome, AuthInitializationCleanupTestFault,
        AuthInitializationFinalLifecycleOutcome, AuthInitializationForwardPhase,
        AuthInitializationPreSourcePhase, AuthInitializationPreSourceRecoveryOutcome,
        AuthInitializationPreSourceRecoveryTestFault, AuthInitializationPrepareOutcome,
        AuthInitializationPrepareTestFault, AuthInitializationReconciliation,
        AuthInitializationRecovery, AuthInitializationRollbackOutcome,
        AuthInitializationRollbackTestFault, AuthInitializationSourceDurabilityTestFault,
        AuthInitializationSourceOutcome, AuthInstanceLayout,
        AuthPlannedRotationActiveKeyInstallOutcome, AuthPlannedRotationActiveKeyInstallTestFault,
        AuthPlannedRotationBlocker, AuthPlannedRotationCleanupOutcome,
        AuthPlannedRotationCleanupTestFault, AuthPlannedRotationFinalLifecycleOutcome,
        AuthPlannedRotationForwardPhase, AuthPlannedRotationPreSourcePhase,
        AuthPlannedRotationPrepareOutcome, AuthPlannedRotationPrepareTestFault,
        AuthPlannedRotationReconciliation, AuthPlannedRotationRecovery,
        AuthPlannedRotationRollbackOutcome, AuthPlannedRotationRollbackTestFault,
        AuthPlannedRotationSourceDurabilityTestFault, AuthPlannedRotationSourceOutcome,
        AuthRetireActiveKeyInstallOutcome, AuthRetireBlocker, AuthRetireCleanupOutcome,
        AuthRetireFinalLifecycleOutcome, AuthRetireForwardPhase, AuthRetirePreSourcePhase,
        AuthRetirePrepareOutcome, AuthRetirePrepareTestFault, AuthRetireReconciliation,
        AuthRetireRecovery, AuthRetireRollbackOutcome, AuthRetireRollbackTestFault,
        AuthRetireSourceOutcome, SecretFsError,
    };
    use crate::auth::transition::AUTH_MAINTENANCE_LOCK_NAME as AUTH_LOCK_FILE_NAME;

    const STORE_DIRECTORY_NAME: &str = "stores";
    const SECRET_DIRECTORY_NAME: &str = "secrets";
    const OTHER_KID: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
    const TEST_TRANSITION: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11,
    ];
    const OTHER_TRANSITION: [u8; 16] = [
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22,
    ];
    const TEST_OWNER: [u8; 16] = [
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x43, 0x33, 0x83, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33,
    ];
    const TEST_AUDIT: [u8; 16] = [
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x84, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44,
    ];
    const PLANNED_TRANSITION: [u8; 16] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45, 0x55, 0x85, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];
    const PLANNED_AUDIT: [u8; 16] = [
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x46, 0x66, 0x86, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66,
    ];
    const RETIRE_TRANSITION: [u8; 16] = [
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x47, 0x77, 0x87, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77,
    ];
    const RETIRE_AUDIT: [u8; 16] = [
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x48, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88,
    ];
    const SOURCE_AT_MICROS: i64 = 1_700_000_000_000_001;
    const RETIRE_AT_MICROS: u64 = SOURCE_AT_MICROS as u64 + 10 + 11 * 60 * 1_000_000;
    const PLANNED_INSTALL_NAME: &str =
        ".auth-keyring-install-55555555-5555-4555-8555-555555555555.tmp";

    struct InitializationFixture {
        metadata: SecretBytes,
        staged: SecretBytes,
        kid: String,
        login_id: &'static str,
        password_phc: Zeroizing<String>,
        recovery_phc: Zeroizing<String>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct PlannedSourceSnapshot {
        lifecycle: (
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            Option<i64>,
            i64,
        ),
        account: (Vec<u8>, i64, i64),
        password: (Vec<u8>, i64),
        recovery: (Vec<u8>, i64),
        audit_count: i64,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ReservationEntrySnapshot {
        name: String,
        device: u64,
        inode: u64,
        links: u64,
        mode: u32,
        bytes: Option<Vec<u8>>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ReservationSnapshot {
        device: u64,
        inode: u64,
        mode: u32,
        entries: Vec<ReservationEntrySnapshot>,
    }

    fn synthetic_verifier(fill: u8) -> ValidatedVerifier {
        let salt = Base64Unpadded::encode_string(&[fill; 16]);
        let output = Base64Unpadded::encode_string(&[fill; 32]);
        ValidatedVerifier::parse(SecretBytes::new(
            format!("$argon2id$v=19$m=65536,t=3,p=4${salt}${output}").into_bytes(),
        ))
        .expect("canonical synthetic verifier")
    }

    fn initialization_fixture(login_id: &'static str) -> InitializationFixture {
        let keyring = Keyring::from_test_seeds(1, SOURCE_AT_MICROS as u64 - 1, [0x31; 32], None)
            .expect("synthetic initialization keyring");
        let password_verifier = synthetic_verifier(0x11);
        let recovery_verifier = synthetic_verifier(0x22);
        let password_phc = Zeroizing::new(password_verifier.expose_phc().to_owned());
        let recovery_phc = Zeroizing::new(recovery_verifier.expose_phc().to_owned());
        let metadata = InitializationMetadataV1::from_keyring(
            InitializationMetadataInput {
                transition_id: TransitionId::from_uuid(Uuid::from_bytes(TEST_TRANSITION))
                    .expect("transition ID"),
                owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(TEST_OWNER)).expect("owner ID"),
                audit_id: AuditId::from_uuid(Uuid::from_bytes(TEST_AUDIT)).expect("audit ID"),
                source_at_micros: SourceTimestampMicros::new(SOURCE_AT_MICROS as u64)
                    .expect("source timestamp"),
                login_id: LoginId::parse(login_id.as_bytes()).expect("login ID"),
                password_verifier,
                recovery_verifier,
            },
            &keyring,
        )
        .expect("initialization metadata")
        .encode()
        .expect("encoded initialization metadata");
        InitializationFixture {
            metadata,
            staged: keyring.encode(),
            kid: keyring.active_kid().as_str().to_owned(),
            login_id,
            password_phc,
            recovery_phc,
        }
    }

    fn initialization_preparation(login_id: &str) -> InitializationPreparationV1 {
        let keyring = Keyring::from_test_seeds(1, SOURCE_AT_MICROS as u64 - 1, [0x31; 32], None)
            .expect("synthetic initialization keyring");
        InitializationPreparationV1::from_keyring(
            InitializationMetadataInput {
                transition_id: TransitionId::from_uuid(Uuid::from_bytes(TEST_TRANSITION))
                    .expect("transition ID"),
                owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(TEST_OWNER)).expect("owner ID"),
                audit_id: AuditId::from_uuid(Uuid::from_bytes(TEST_AUDIT)).expect("audit ID"),
                source_at_micros: SourceTimestampMicros::new(SOURCE_AT_MICROS as u64)
                    .expect("source timestamp"),
                login_id: LoginId::parse(login_id.as_bytes()).expect("login ID"),
                password_verifier: synthetic_verifier(0x11),
                recovery_verifier: synthetic_verifier(0x22),
            },
            &keyring,
        )
        .expect("initialization preparation")
    }

    fn planned_rotation_input() -> PlannedRotationMetadataInput {
        PlannedRotationMetadataInput {
            transition_id: TransitionId::from_uuid(Uuid::from_bytes(PLANNED_TRANSITION))
                .expect("planned transition ID"),
            owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(TEST_OWNER))
                .expect("planned owner ID"),
            audit_id: AuditId::from_uuid(Uuid::from_bytes(PLANNED_AUDIT))
                .expect("planned audit ID"),
            key_activated_at_micros: AuthTimestampMicros::new(SOURCE_AT_MICROS as u64 + 10)
                .expect("planned activation"),
            source_at_micros: SourceTimestampMicros::new(SOURCE_AT_MICROS as u64 + 11)
                .expect("planned source timestamp"),
            expected_lifecycle_revision: 2,
            expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(
                SOURCE_AT_MICROS as u64,
            )
            .expect("active lifecycle timestamp"),
            credential_version: 1,
            account_revision: 1,
            password_credential_revision: 1,
            recovery_credential_revision: 1,
        }
    }

    fn current_active_keyring(root: &Path) -> Keyring {
        let bytes = fs::read(root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1"))
            .expect("current active keyring");
        Keyring::decode(SecretBytes::new(bytes)).expect("canonical current active keyring")
    }

    fn planned_rotation_preparation(root: &Path) -> PlannedRotationPreparationV1 {
        let current = current_active_keyring(root);
        let staged = current
            .planned_rotation_from_test_seed(SOURCE_AT_MICROS as u64 + 10, [0x41; 32])
            .expect("fixed planned staged keyring");
        PlannedRotationPreparationV1::from_keyrings(planned_rotation_input(), &current, staged)
            .expect("planned rotation preparation")
    }

    fn planned_rotation_preparation_with_input(
        root: &Path,
        input: PlannedRotationMetadataInput,
    ) -> PlannedRotationPreparationV1 {
        let current = current_active_keyring(root);
        let staged = current
            .planned_rotation_from_test_seed(SOURCE_AT_MICROS as u64 + 10, [0x41; 32])
            .expect("fixed planned staged keyring");
        PlannedRotationPreparationV1::from_keyrings(input, &current, staged)
            .expect("planned rotation preparation")
    }

    fn retire_input() -> RetireMetadataInput {
        RetireMetadataInput {
            transition_id: TransitionId::from_uuid(Uuid::from_bytes(RETIRE_TRANSITION))
                .expect("retire transition ID"),
            owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(TEST_OWNER))
                .expect("retire owner ID"),
            audit_id: AuditId::from_uuid(Uuid::from_bytes(RETIRE_AUDIT)).expect("retire audit ID"),
            source_at_micros: SourceTimestampMicros::new(RETIRE_AT_MICROS)
                .expect("retire source timestamp"),
            expected_lifecycle_revision: 4,
            expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(
                SOURCE_AT_MICROS as u64 + 11,
            )
            .expect("planned final lifecycle timestamp"),
            credential_version: 1,
            account_revision: 1,
            password_credential_revision: 1,
            recovery_credential_revision: 1,
        }
    }

    fn retire_preparation(root: &Path) -> RetirePreparationV1 {
        RetirePreparationV1::from_current_keyring(retire_input(), &current_active_keyring(root))
            .expect("retire preparation")
    }

    fn retire_preparation_with_input(
        root: &Path,
        input: RetireMetadataInput,
    ) -> RetirePreparationV1 {
        RetirePreparationV1::from_current_keyring(input, &current_active_keyring(root))
            .expect("retire preparation")
    }

    fn owner_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("owner-only file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner-only file mode");
    }

    fn find_only_reservation(secrets: &Path, prefix: &str) -> PathBuf {
        let matches: Vec<PathBuf> = fs::read_dir(secrets)
            .expect("secret directory inventory")
            .map(|entry| entry.expect("secret directory entry"))
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(prefix))
                    .then(|| entry.path())
            })
            .collect();
        assert_eq!(matches.len(), 1, "exactly one retained reservation");
        matches.into_iter().next().expect("only reservation")
    }

    fn reservation_snapshot(path: &Path) -> ReservationSnapshot {
        let directory = fs::symlink_metadata(path).expect("reservation snapshot metadata");
        let mut entries: Vec<ReservationEntrySnapshot> = fs::read_dir(path)
            .expect("reservation snapshot inventory")
            .map(|entry| {
                let entry = entry.expect("reservation snapshot entry");
                let metadata =
                    fs::symlink_metadata(entry.path()).expect("reservation entry metadata");
                ReservationEntrySnapshot {
                    name: entry
                        .file_name()
                        .into_string()
                        .expect("canonical reservation entry"),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    links: metadata.nlink(),
                    mode: metadata.permissions().mode() & 0o7777,
                    bytes: metadata
                        .file_type()
                        .is_file()
                        .then(|| fs::read(entry.path()).expect("reservation entry bytes")),
                }
            })
            .collect();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        ReservationSnapshot {
            device: directory.dev(),
            inode: directory.ino(),
            mode: directory.permissions().mode() & 0o7777,
            entries,
        }
    }

    fn assert_uninitialized_auth_source(database: &Path) {
        let reader = RawConnection::open(database).expect("read initialization source");
        assert_eq!(
            reader
                .query_row(
                    "SELECT state FROM auth_key_lifecycle WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("lifecycle state"),
            "uninitialized"
        );
        for table in [
            "auth_accounts",
            "auth_password_credentials",
            "auth_recovery_credentials",
            "auth_authenticator_throttles",
            "auth_login_control",
            "auth_audit",
        ] {
            let count = reader
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("auth table count");
            assert_eq!(count, 0, "{table} remains empty");
        }
    }

    fn auth_audit_shape(database: &Path) -> (i64, Option<i64>) {
        let reader = RawConnection::open(database).expect("read auth audit shape");
        let audit_count = reader
            .query_row("SELECT count(*) FROM auth_audit", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("auth audit count");
        let audit_sequence = reader
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'auth_audit'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .ok();
        (audit_count, audit_sequence)
    }

    fn auth_lifecycle_state(database: &Path) -> String {
        RawConnection::open(database)
            .expect("read auth lifecycle")
            .query_row(
                "SELECT state FROM auth_key_lifecycle WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("auth lifecycle state")
    }

    fn planned_source_snapshot(database: &Path) -> PlannedSourceSnapshot {
        let reader = RawConnection::open(database).expect("planned source reader");
        PlannedSourceSnapshot {
            lifecycle: reader
                .query_row(
                    "SELECT
                        state, state_revision, expected_kid, transition_kind, transition_id,
                        keyring_version, updated_at_micros
                     FROM auth_key_lifecycle WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .expect("planned lifecycle snapshot"),
            account: reader
                .query_row(
                    "SELECT owner_id, credential_version, account_revision
                     FROM auth_accounts WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("planned account snapshot"),
            password: reader
                .query_row(
                    "SELECT owner_id, credential_revision
                     FROM auth_password_credentials WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("planned password snapshot"),
            recovery: reader
                .query_row(
                    "SELECT owner_id, credential_revision
                     FROM auth_recovery_credentials WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("planned recovery snapshot"),
            audit_count: reader
                .query_row("SELECT count(*) FROM auth_audit", [], |row| row.get(0))
                .expect("planned audit count"),
        }
    }

    fn persisted_legacy_policy_provenance(database: &Path) -> String {
        RawConnection::open(database)
            .expect("legacy policy provenance reader")
            .query_row(
                "SELECT blocklist_version
                 FROM auth_password_credentials
                 WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("persisted legacy policy provenance")
    }

    async fn advance_initialization_to_installed_active_key(actor: &AuthMaintenanceActor) {
        assert_eq!(
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("prepared initialization"),
            AuthInitializationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_initialization_source()
                .await
                .expect("committed initialization source"),
            AuthInitializationSourceOutcome::Committed
        );
        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("installed initialization active key"),
            AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
    }

    async fn advance_initialization_to_awaiting_cleanup(actor: &AuthMaintenanceActor) {
        advance_initialization_to_installed_active_key(actor).await;
        assert_eq!(
            actor
                .commit_initialization_final_lifecycle()
                .await
                .expect("activated initialization lifecycle"),
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
    }

    async fn advance_initialization_to_clean_active(actor: &AuthMaintenanceActor) {
        advance_initialization_to_awaiting_cleanup(actor).await;
        assert_eq!(
            actor
                .cleanup_initialization()
                .await
                .expect("clean initialization evidence"),
            AuthInitializationCleanupOutcome::Completed
        );
    }

    async fn advance_planned_rotation_to_awaiting_final_db_cas(
        actor: &AuthMaintenanceActor,
        root: &Path,
    ) {
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(root))
                .await
                .expect("prepared planned rotation"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_planned_rotation_source()
                .await
                .expect("committed planned source"),
            AuthPlannedRotationSourceOutcome::Committed
        );
        assert_eq!(
            actor
                .install_planned_rotation_active_key()
                .await
                .expect("installed planned active key"),
            AuthPlannedRotationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
    }

    async fn advance_planned_rotation_to_awaiting_cleanup(
        actor: &AuthMaintenanceActor,
        root: &Path,
    ) {
        advance_planned_rotation_to_awaiting_final_db_cas(actor, root).await;
        assert_eq!(
            actor
                .commit_planned_rotation_final_lifecycle()
                .await
                .expect("committed planned final lifecycle"),
            AuthPlannedRotationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
    }

    async fn advance_planned_rotation_to_complete(actor: &AuthMaintenanceActor, root: &Path) {
        advance_planned_rotation_to_awaiting_cleanup(actor, root).await;
        assert_eq!(
            actor
                .cleanup_planned_rotation()
                .await
                .expect("clean planned rotation evidence"),
            AuthPlannedRotationCleanupOutcome::Completed
        );
    }

    async fn advance_retire_to_awaiting_final_db_cas(actor: &AuthMaintenanceActor, root: &Path) {
        assert_eq!(
            actor
                .prepare_retire(retire_preparation(root))
                .await
                .expect("prepared retire"),
            AuthRetirePrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_retire_source()
                .await
                .expect("committed retire source"),
            AuthRetireSourceOutcome::Committed
        );
        assert_eq!(
            actor
                .install_retire_active_key()
                .await
                .expect("installed retired active key"),
            AuthRetireActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
    }

    async fn advance_retire_to_awaiting_cleanup(actor: &AuthMaintenanceActor, root: &Path) {
        advance_retire_to_awaiting_final_db_cas(actor, root).await;
        assert_eq!(
            actor
                .commit_retire_final_lifecycle()
                .await
                .expect("committed retire final lifecycle"),
            AuthRetireFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
    }

    fn legacy_policy_provenance() -> String {
        let mut value = NO_BLOCKLIST_CHECK_SENTINEL.as_bytes().to_vec();
        let last = value.len() - 1;
        value[last] = if value[last] == b'0' { b'1' } else { b'0' };
        String::from_utf8(value).expect("legacy policy provenance ASCII")
    }

    fn legacy_metadata(metadata: &SecretBytes) -> SecretBytes {
        let mut bytes = Zeroizing::new(metadata.expose_secret().to_vec());
        let checksum_offset = bytes.len() - 32;
        let mut cursor = 166;
        let login_length = usize::from(bytes[cursor]);
        cursor += 1 + login_length;
        let password_length = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2 + password_length;
        let recovery_length = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2 + recovery_length;
        let provenance_length = usize::from(bytes[cursor]);
        cursor += 1;
        assert_eq!(
            &bytes[cursor..cursor + provenance_length],
            NO_BLOCKLIST_CHECK_SENTINEL.as_bytes()
        );
        bytes[cursor..cursor + provenance_length]
            .copy_from_slice(legacy_policy_provenance().as_bytes());
        let checksum = Sha256::digest(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
        SecretBytes::from_zeroizing(bytes)
    }

    fn write_prepared_reservation(
        root: &Path,
        fixture: &InitializationFixture,
        metadata: &SecretBytes,
    ) -> std::path::PathBuf {
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        fs::create_dir(&reservation).expect("initialization reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))
            .expect("owner-only reservation");
        owner_file(&reservation.join("metadata"), metadata.expose_secret());
        owner_file(
            &reservation.join("staged-keyring"),
            fixture.staged.expose_secret(),
        );
        owner_file(&reservation.join("prepared"), b"");
        reservation
    }

    fn write_pre_source_reservation(
        root: &Path,
        fixture: &InitializationFixture,
        metadata: &SecretBytes,
        phase: AuthInitializationPreSourcePhase,
    ) -> std::path::PathBuf {
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        fs::create_dir(&reservation).expect("initialization reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))
            .expect("owner-only reservation");

        match phase {
            AuthInitializationPreSourcePhase::ReservationOnly => {}
            AuthInitializationPreSourcePhase::MetadataIncomplete => {
                owner_file(&reservation.join("metadata"), b"POV");
            }
            AuthInitializationPreSourcePhase::MetadataComplete => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
            }
            AuthInitializationPreSourcePhase::StagedIncomplete => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
                owner_file(
                    &reservation.join("staged-keyring"),
                    &fixture.staged.expose_secret()[..fixture.staged.expose_secret().len() - 1],
                );
            }
            AuthInitializationPreSourcePhase::StagedComplete => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
                owner_file(
                    &reservation.join("staged-keyring"),
                    fixture.staged.expose_secret(),
                );
            }
            AuthInitializationPreSourcePhase::Prepared => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
                owner_file(
                    &reservation.join("staged-keyring"),
                    fixture.staged.expose_secret(),
                );
                owner_file(&reservation.join("prepared"), b"");
            }
        }
        reservation
    }

    fn write_planned_pre_source_reservation(
        root: &Path,
        preparation: &PlannedRotationPreparationV1,
        phase: AuthPlannedRotationPreSourcePhase,
    ) -> std::path::PathBuf {
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        fs::create_dir(&reservation).expect("planned reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))
            .expect("owner-only planned reservation");
        let metadata = preparation
            .encoded_metadata()
            .expect("planned metadata bytes");
        let staged = preparation.staged_keyring_bytes();

        match phase {
            AuthPlannedRotationPreSourcePhase::ReservationOnly => {}
            AuthPlannedRotationPreSourcePhase::MetadataIncomplete => {
                owner_file(&reservation.join("metadata"), b"POV");
            }
            AuthPlannedRotationPreSourcePhase::MetadataComplete => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
            }
            AuthPlannedRotationPreSourcePhase::StagedIncomplete => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
                owner_file(
                    &reservation.join("staged-keyring"),
                    &staged[..staged.len() - 1],
                );
            }
            AuthPlannedRotationPreSourcePhase::StagedComplete => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
                owner_file(&reservation.join("staged-keyring"), staged);
            }
            AuthPlannedRotationPreSourcePhase::Prepared => {
                owner_file(&reservation.join("metadata"), metadata.expose_secret());
                owner_file(&reservation.join("staged-keyring"), staged);
                owner_file(&reservation.join("prepared"), b"");
            }
        }
        reservation
    }

    fn commit_initializing_source(database: &Path, fixture: &InitializationFixture) {
        commit_initializing_source_with_provenance(database, fixture, NO_BLOCKLIST_CHECK_SENTINEL);
    }

    fn commit_initializing_source_with_provenance(
        database: &Path,
        fixture: &InitializationFixture,
        legacy_policy_provenance: &str,
    ) {
        let mut writer = RawConnection::open(database).expect("initialization source writer");
        writer
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable foreign keys");
        let transaction = writer
            .transaction()
            .expect("initialization source transaction");
        transaction
            .execute(
                "INSERT INTO auth_accounts(
                    singleton, owner_id, login_id, account_state, credential_version,
                    account_revision, created_at_micros, updated_at_micros
                 ) VALUES (1, ?1, ?2, 'enabled', 1, 1, ?3, ?3)",
                params![TEST_OWNER, fixture.login_id, SOURCE_AT_MICROS],
            )
            .expect("initial account");
        transaction
            .execute(
                "INSERT INTO auth_password_credentials(
                    singleton, owner_id, verifier_phc, authenticator_state,
                    credential_revision, blocklist_version, created_at_micros,
                    updated_at_micros
                 ) VALUES (1, ?1, ?2, 'enabled', 1, ?3, ?4, ?4)",
                params![
                    TEST_OWNER,
                    fixture.password_phc.as_str(),
                    legacy_policy_provenance,
                    SOURCE_AT_MICROS
                ],
            )
            .expect("initial password credential");
        transaction
            .execute(
                "INSERT INTO auth_recovery_credentials(
                    singleton, owner_id, verifier_phc, credential_revision,
                    created_at_micros, updated_at_micros
                 ) VALUES (1, ?1, ?2, 1, ?3, ?3)",
                params![TEST_OWNER, fixture.recovery_phc.as_str(), SOURCE_AT_MICROS],
            )
            .expect("initial recovery credential");
        for authenticator in ["password", "recovery"] {
            transaction
                .execute(
                    "INSERT INTO auth_authenticator_throttles(
                        owner_id, authenticator, failure_count, next_allowed_at_micros,
                        throttle_revision, updated_at_micros
                     ) VALUES (?1, ?2, 0, 0, 1, ?3)",
                    params![TEST_OWNER, authenticator, SOURCE_AT_MICROS],
                )
                .expect("initial throttle");
        }
        transaction
            .execute(
                "INSERT INTO auth_login_control(
                    singleton, owner_id, admission_revision, clock_floor_micros,
                    control_revision, created_at_micros, updated_at_micros
                 ) VALUES (1, ?1, 1, ?2, 1, ?2, ?2)",
                params![TEST_OWNER, SOURCE_AT_MICROS],
            )
            .expect("initial login control");
        transaction
            .execute(
                "INSERT INTO auth_audit(
                    owner_id, audit_id, action, profile, session_id, attempt_id,
                    happened_at_micros
                 ) VALUES (?1, ?2, 'auth_initialized', NULL, NULL, NULL, ?3)",
                params![TEST_OWNER, TEST_AUDIT, SOURCE_AT_MICROS],
            )
            .expect("initial audit");
        transaction
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = ?3
                 WHERE singleton = 1 AND state = 'uninitialized'",
                params![fixture.kid, TEST_TRANSITION, SOURCE_AT_MICROS],
            )
            .expect("initializing lifecycle");
        transaction.commit().expect("initialization source commit");
    }

    async fn actor_and_stores(root: &Path) -> (AuthMaintenanceActor, StoreSet) {
        let layout = AuthInstanceLayout::open_or_create(root).expect("instance layout");
        let stores = StoreSet::open(root.join(STORE_DIRECTORY_NAME))
            .await
            .expect("stores");
        let context = layout
            .lock()
            .expect("maintenance lock")
            .bind_conversation(&stores.conversation)
            .expect("conversation binding");
        let actor = AuthMaintenanceActor::start(context).expect("maintenance actor");
        (actor, stores)
    }

    async fn owned_context_and_stores(root: &Path) -> (OwnedAuthMaintenanceContext, StoreSet) {
        let layout = AuthInstanceLayout::open_or_create(root).expect("instance layout");
        let stores = StoreSet::open(root.join(STORE_DIRECTORY_NAME))
            .await
            .expect("stores");
        let context = layout
            .lock()
            .expect("maintenance lock")
            .bind_conversation(&stores.conversation)
            .expect("conversation binding")
            .into_owned()
            .expect("owned maintenance context");
        (context, stores)
    }

    #[cfg(target_os = "macos")]
    fn add_extended_acl(path: &Path) {
        let mode_before = fs::symlink_metadata(path)
            .expect("ACL target metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert!(matches!(mode_before, 0o600 | 0o700));
        let output = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(path)
            .output()
            .expect("run macOS chmod ACL command");
        assert!(
            output.status.success(),
            "macOS chmod ACL command failed with status {:?}",
            output.status.code()
        );
        assert_eq!(
            fs::symlink_metadata(path)
                .expect("ACL target metadata after chmod")
                .permissions()
                .mode()
                & 0o7777,
            mode_before,
            "extended ACL must not rely on a traditional-mode mismatch"
        );
    }

    #[tokio::test]
    async fn actor_owns_exact_binding_and_lock_until_joined_shutdown() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;

        let run = actor.start_revalidation().expect("actor revalidation");
        let rendered = format!("{actor:?} {run:?}");
        assert!(rendered.contains("[DETACHED]"));
        assert!(rendered.contains("[PENDING]"));
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));
        run.await.expect("actor revalidation");
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        actor.shutdown().await.expect("joined shutdown");
        AuthInstanceLayout::open_or_create(&root)
            .expect("layout after shutdown")
            .lock()
            .expect("joined shutdown releases lock");
        stores
            .conversation
            .report()
            .await
            .expect("normal shutdown does not poison store");
    }

    #[tokio::test]
    async fn actor_persists_clean_initialization_preparation_without_database_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let preparation = initialization_preparation("owner_01");
        let rendered = format!("{preparation:?}");
        assert_eq!(rendered, "InitializationPreparationV1([REDACTED])");
        assert!(!rendered.contains(fixture.login_id));
        assert!(!rendered.contains(fixture.kid.as_str()));
        assert!(!rendered.contains(fixture.password_phc.as_str()));
        assert!(!rendered.contains(fixture.recovery_phc.as_str()));
        let (actor, stores) = actor_and_stores(&root).await;

        let outcome = actor
            .prepare_initialization(preparation)
            .await
            .expect("durable pre-source preparation");
        assert_eq!(outcome, AuthInitializationPrepareOutcome::Prepared);
        assert_eq!(
            format!("{outcome:?}"),
            "AuthInitializationPrepareOutcome::Prepared"
        );

        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("metadata readback"),
            fixture.metadata.expose_secret()
        );
        assert_eq!(
            fs::read(reservation.join("staged-keyring")).expect("staged keyring readback"),
            fixture.staged.expose_secret()
        );
        assert_eq!(
            fs::read(reservation.join("prepared")).expect("prepared sentinel readback"),
            b""
        );
        assert_eq!(
            fs::symlink_metadata(&reservation)
                .expect("reservation metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        for name in ["metadata", "staged-keyring", "prepared"] {
            assert_eq!(
                fs::symlink_metadata(reservation.join(name))
                    .expect("reservation entry metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o600
            );
        }
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("prepared readback"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            }
        );

        assert_uninitialized_auth_source(&database);

        stores
            .conversation
            .report()
            .await
            .expect("successful preparation does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn zero_source_timestamp_is_rejected_before_any_preparation_artifact() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secret_root = root.join(SECRET_DIRECTORY_NAME);
        let (actor, stores) = actor_and_stores(&root).await;
        let keyring = Keyring::from_test_seeds(1, 0, [0x31; 32], None)
            .expect("zero-time synthetic initialization keyring");

        let error = InitializationPreparationV1::from_keyring(
            InitializationMetadataInput {
                transition_id: TransitionId::from_uuid(Uuid::from_bytes(TEST_TRANSITION))
                    .expect("transition ID"),
                owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(TEST_OWNER)).expect("owner ID"),
                audit_id: AuditId::from_uuid(Uuid::from_bytes(TEST_AUDIT)).expect("audit ID"),
                source_at_micros: SourceTimestampMicros::new(0).expect("typed zero timestamp"),
                login_id: LoginId::parse(b"owner_01").expect("login ID"),
                password_verifier: synthetic_verifier(0x11),
                recovery_verifier: synthetic_verifier(0x22),
            },
            &keyring,
        )
        .unwrap_err();
        assert_eq!(error, TransitionContractError::InvalidMetadata);
        let entries: Vec<OsString> = fs::read_dir(&secret_root)
            .expect("secret inventory")
            .map(|entry| entry.expect("secret entry").file_name())
            .collect();
        assert_eq!(entries, [OsString::from(AUTH_LOCK_FILE_NAME)]);
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("clean after rejected plan"),
            AuthInitializationReconciliation::CleanUninitialized
        );
        stores
            .conversation
            .report()
            .await
            .expect("invalid plan never reaches actor");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn duplicate_initialization_preparation_is_typed_no_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        assert_eq!(
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("first preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let directory_modified = fs::symlink_metadata(&reservation)
            .expect("reservation metadata")
            .modified()
            .expect("reservation modified time");
        let metadata_before =
            fs::read(reservation.join("metadata")).expect("metadata before retry");
        let staged_before =
            fs::read(reservation.join("staged-keyring")).expect("staged before retry");

        let outcome = actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("typed duplicate preparation");
        assert_eq!(
            outcome,
            AuthInitializationPrepareOutcome::PreconditionNotClean(
                AuthInitializationReconciliation::InitializePreSource {
                    phase: AuthInitializationPreSourcePhase::Prepared,
                    recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
                }
            )
        );
        let rendered = format!("{outcome:?}");
        assert_eq!(
            rendered,
            "AuthInitializationPrepareOutcome::PreconditionNotClean([REDACTED])"
        );
        assert!(!rendered.contains(fixture.login_id));
        assert_eq!(
            fs::symlink_metadata(&reservation)
                .expect("reservation metadata after retry")
                .modified()
                .expect("reservation modified time after retry"),
            directory_modified
        );
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("metadata after retry"),
            metadata_before
        );
        assert_eq!(
            fs::read(reservation.join("staged-keyring")).expect("staged after retry"),
            staged_before
        );
        assert!(reservation.join("prepared").is_file());

        stores
            .conversation
            .report()
            .await
            .expect("typed duplicate does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn recognized_artifact_race_before_mutation_is_typed_and_preserved() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secret_root = root.join(SECRET_DIRECTORY_NAME);
        let (actor, stores) = actor_and_stores(&root).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_prepare_initialization_with_pre_mutation_gate(
                initialization_preparation("owner_01"),
                gate.clone(),
            )
            .expect("gated pre-mutation preparation");
        gate.wait_until_reached();

        let raced_reservation =
            secret_root.join(".auth-transition-initialize-22222222-2222-4222-8222-222222222222");
        fs::create_dir(&raced_reservation).expect("recognized raced reservation");
        fs::set_permissions(&raced_reservation, fs::Permissions::from_mode(0o700))
            .expect("owner-only raced reservation");
        gate.resume();

        assert_eq!(
            run.await.expect("typed raced precondition"),
            AuthInitializationPrepareOutcome::PreconditionNotClean(
                AuthInitializationReconciliation::InitializePreSource {
                    phase: AuthInitializationPreSourcePhase::ReservationOnly,
                    recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                }
            )
        );
        assert!(raced_reservation.is_dir());
        assert_eq!(
            fs::read_dir(&raced_reservation)
                .expect("raced evidence inventory")
                .count(),
            0
        );
        assert!(
            !secret_root
                .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111")
                .exists()
        );
        stores
            .conversation
            .report()
            .await
            .expect("recognized raced precondition does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn every_pre_source_durability_failure_poisons_and_preserves_exact_phase() {
        let cases: [(
            AuthInitializationPrepareTestFault,
            &[&str],
            AuthInitializationPreSourcePhase,
            AuthInitializationRecovery,
        ); 4] = [
            (
                AuthInitializationPrepareTestFault::Reservation,
                &[],
                AuthInitializationPreSourcePhase::ReservationOnly,
                AuthInitializationRecovery::RollbackOnlyCandidate,
            ),
            (
                AuthInitializationPrepareTestFault::Metadata,
                &["metadata"],
                AuthInitializationPreSourcePhase::MetadataComplete,
                AuthInitializationRecovery::RollbackOnlyCandidate,
            ),
            (
                AuthInitializationPrepareTestFault::Staged,
                &["metadata", "staged-keyring"],
                AuthInitializationPreSourcePhase::StagedComplete,
                AuthInitializationRecovery::ResumeOrRollbackCandidate,
            ),
            (
                AuthInitializationPrepareTestFault::Prepared,
                &["metadata", "prepared", "staged-keyring"],
                AuthInitializationPreSourcePhase::Prepared,
                AuthInitializationRecovery::ResumeOrRollbackCandidate,
            ),
        ];

        for (fault, expected_entries, phase, recovery) in cases {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let fixture = initialization_fixture("owner_01");
            let (actor, stores) = actor_and_stores(&root).await;

            let error = actor
                .start_prepare_initialization_with_fault(
                    initialization_preparation("owner_01"),
                    fault,
                )
                .expect("admitted fault-injected preparation")
                .await
                .unwrap_err();
            assert_eq!(
                error,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(std::io::ErrorKind::Other)
                ))
            );
            let reservation = root
                .join(SECRET_DIRECTORY_NAME)
                .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
            let mut actual_entries: Vec<String> = fs::read_dir(&reservation)
                .expect("partial reservation inventory")
                .map(|entry| {
                    entry
                        .expect("partial reservation entry")
                        .file_name()
                        .into_string()
                        .expect("canonical reservation entry")
                })
                .collect();
            actual_entries.sort();
            assert_eq!(actual_entries, expected_entries);
            if expected_entries.contains(&"metadata") {
                assert_eq!(
                    fs::read(reservation.join("metadata")).expect("metadata evidence retained"),
                    fixture.metadata.expose_secret()
                );
            }
            if expected_entries.contains(&"staged-keyring") {
                assert_eq!(
                    fs::read(reservation.join("staged-keyring"))
                        .expect("staged keyring evidence retained"),
                    fixture.staged.expose_secret()
                );
            }
            if expected_entries.contains(&"prepared") {
                assert_eq!(
                    fs::read(reservation.join("prepared")).expect("prepared sentinel retained"),
                    b""
                );
            }
            assert_uninitialized_auth_source(&database);
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
            assert_eq!(
                actor
                    .inspect_initialization_reconciliation()
                    .await
                    .unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(
                AuthInstanceLayout::open_or_create(&root)
                    .expect("contending layout")
                    .lock()
                    .unwrap_err(),
                SecretFsError::AlreadyLocked
            );

            actor.shutdown().await.expect("joined poisoned shutdown");
            drop(stores);
            let (recovery_actor, recovery_stores) = actor_and_stores(&root).await;
            assert_eq!(
                recovery_actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("exact retained pre-source phase"),
                AuthInitializationReconciliation::InitializePreSource { phase, recovery }
            );
            recovery_stores
                .conversation
                .report()
                .await
                .expect("fresh store can inspect retained evidence");
            recovery_actor
                .shutdown()
                .await
                .expect("joined recovery actor");
        }
    }

    #[tokio::test]
    async fn dropped_preparation_receiver_does_not_cancel_actor_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_prepare_initialization_with_gate(
                initialization_preparation("owner_01"),
                gate.clone(),
            )
            .expect("gated initialization preparation");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();

        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("preparation waiter is cancelled")
                .is_cancelled()
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        gate.resume();
        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected actor error after receiver drop: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached preparation")
        .expect("prepared reconciliation");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            }
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop after admission does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_pre_source_recovery_prepares_replays_and_supports_both_next_steps() {
        let directory = tempdir().expect("temporary parent");

        let source_root = directory.path().join("source");
        let source_database = source_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let source_fixture = initialization_fixture("owner_01");
        let (source_actor, source_stores) = actor_and_stores(&source_root).await;
        let source_reservation = write_pre_source_reservation(
            &source_root,
            &source_fixture,
            &source_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let staged_snapshot = reservation_snapshot(&source_reservation);

        let prepared = source_actor
            .recover_initialization_pre_source()
            .await
            .expect("recover staged-complete initialization");
        assert_eq!(
            prepared,
            AuthInitializationPreSourceRecoveryOutcome::Prepared
        );
        assert_eq!(
            format!("{prepared:?}"),
            "AuthInitializationPreSourceRecoveryOutcome::Prepared"
        );
        let prepared_snapshot = reservation_snapshot(&source_reservation);
        for original in &staged_snapshot.entries {
            assert_eq!(
                prepared_snapshot
                    .entries
                    .iter()
                    .find(|entry| entry.name == original.name),
                Some(original),
                "metadata and staged keyring remain byte- and inode-identical"
            );
        }
        assert_eq!(
            prepared_snapshot
                .entries
                .iter()
                .map(|entry| (entry.name.as_str(), entry.mode, entry.bytes.as_deref()))
                .collect::<Vec<_>>(),
            [
                (
                    "metadata",
                    0o600,
                    Some(source_fixture.metadata.expose_secret())
                ),
                ("prepared", 0o600, Some(&[][..])),
                (
                    "staged-keyring",
                    0o600,
                    Some(source_fixture.staged.expose_secret())
                ),
            ]
        );
        assert_eq!(prepared_snapshot.mode, 0o700);
        assert_uninitialized_auth_source(&source_database);
        assert_eq!(auth_audit_shape(&source_database), (0, None));

        let replay = source_actor
            .recover_initialization_pre_source()
            .await
            .expect("replay prepared recovery");
        assert_eq!(
            replay,
            AuthInitializationPreSourceRecoveryOutcome::AlreadyPrepared
        );
        assert_eq!(
            format!("{replay:?}"),
            "AuthInitializationPreSourceRecoveryOutcome::AlreadyPrepared"
        );
        assert_eq!(
            reservation_snapshot(&source_reservation),
            prepared_snapshot,
            "prepared replay must not rewrite any artifact"
        );
        assert_eq!(
            source_actor
                .commit_initialization_source()
                .await
                .expect("source CAS after recovered preparation"),
            AuthInitializationSourceOutcome::Committed
        );
        assert_eq!(auth_lifecycle_state(&source_database), "initializing");
        source_stores
            .conversation
            .report()
            .await
            .expect("recovered source path keeps store healthy");
        source_actor
            .shutdown()
            .await
            .expect("source actor shutdown");

        let rollback_root = directory.path().join("rollback");
        let rollback_database = rollback_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let rollback_fixture = initialization_fixture("owner_01");
        let (rollback_actor, rollback_stores) = actor_and_stores(&rollback_root).await;
        let rollback_reservation = write_pre_source_reservation(
            &rollback_root,
            &rollback_fixture,
            &rollback_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        assert_eq!(
            rollback_actor
                .recover_initialization_pre_source()
                .await
                .expect("recover before rollback"),
            AuthInitializationPreSourceRecoveryOutcome::Prepared
        );
        assert_eq!(
            rollback_actor
                .rollback_initialization_pre_source()
                .await
                .expect("rollback recovered preparation"),
            AuthInitializationRollbackOutcome::RolledBack
        );
        assert!(!rollback_reservation.exists());
        assert_uninitialized_auth_source(&rollback_database);
        assert_eq!(auth_audit_shape(&rollback_database), (0, None));
        rollback_stores
            .conversation
            .report()
            .await
            .expect("recovered rollback keeps store healthy");
        rollback_actor
            .shutdown()
            .await
            .expect("rollback actor shutdown");
    }

    #[tokio::test]
    async fn initialization_pre_source_recovery_rejects_ineligible_states_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let partial_phases = [
            AuthInitializationPreSourcePhase::ReservationOnly,
            AuthInitializationPreSourcePhase::MetadataIncomplete,
            AuthInitializationPreSourcePhase::MetadataComplete,
            AuthInitializationPreSourcePhase::StagedIncomplete,
        ];

        for (index, phase) in partial_phases.into_iter().enumerate() {
            let root = directory.path().join(format!("partial-{index}"));
            let fixture = initialization_fixture("owner_01");
            let (actor, stores) = actor_and_stores(&root).await;
            let reservation =
                write_pre_source_reservation(&root, &fixture, &fixture.metadata, phase);
            let before = reservation_snapshot(&reservation);
            let outcome = actor
                .recover_initialization_pre_source()
                .await
                .expect("typed partial-state rejection");
            assert_eq!(
                outcome,
                AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                    AuthInitializationReconciliation::InitializePreSource {
                        phase,
                        recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                    }
                ),
                "{phase:?}"
            );
            assert_eq!(
                reservation_snapshot(&reservation),
                before,
                "{phase:?} must remain byte- and inode-identical"
            );
            assert_eq!(
                format!("{outcome:?}"),
                "AuthInitializationPreSourceRecoveryOutcome::NotRecoverable([REDACTED])"
            );
            stores
                .conversation
                .report()
                .await
                .expect("partial rejection keeps store healthy");
            actor.shutdown().await.expect("partial actor shutdown");
        }

        for (index, phase) in [
            AuthInitializationPreSourcePhase::MetadataComplete,
            AuthInitializationPreSourcePhase::StagedIncomplete,
            AuthInitializationPreSourcePhase::StagedComplete,
            AuthInitializationPreSourcePhase::Prepared,
        ]
        .into_iter()
        .enumerate()
        {
            let root = directory.path().join(format!("historical-{index}"));
            let fixture = initialization_fixture("owner_01");
            let historical = legacy_metadata(&fixture.metadata);
            let (actor, stores) = actor_and_stores(&root).await;
            let reservation = write_pre_source_reservation(&root, &fixture, &historical, phase);
            let before = reservation_snapshot(&reservation);
            let outcome = actor
                .recover_initialization_pre_source()
                .await
                .expect("typed historical-state rejection");
            assert_eq!(
                outcome,
                AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                    AuthInitializationReconciliation::InitializePreSource {
                        phase,
                        recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                    }
                ),
                "{phase:?}"
            );
            assert_eq!(
                reservation_snapshot(&reservation),
                before,
                "historical {phase:?} must not advance"
            );
            stores
                .conversation
                .report()
                .await
                .expect("historical rejection keeps store healthy");
            actor.shutdown().await.expect("historical actor shutdown");
        }

        let clean_root = directory.path().join("clean");
        let (clean_actor, clean_stores) = actor_and_stores(&clean_root).await;
        assert_eq!(
            clean_actor
                .recover_initialization_pre_source()
                .await
                .expect("clean typed rejection"),
            AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                AuthInitializationReconciliation::CleanUninitialized
            )
        );
        clean_stores
            .conversation
            .report()
            .await
            .expect("clean rejection keeps store healthy");
        clean_actor.shutdown().await.expect("clean actor shutdown");

        let forward_root = directory.path().join("forward");
        let forward_database = forward_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let (forward_actor, forward_stores) = actor_and_stores(&forward_root).await;
        assert_eq!(
            forward_actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("forward preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        let forward_reservation = forward_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        assert_eq!(
            forward_actor
                .commit_initialization_source()
                .await
                .expect("forward source"),
            AuthInitializationSourceOutcome::Committed
        );
        let forward_before = reservation_snapshot(&forward_reservation);
        assert!(matches!(
            forward_actor
                .recover_initialization_pre_source()
                .await
                .expect("forward typed rejection"),
            AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                AuthInitializationReconciliation::InitializeForwardOnly(_)
            )
        ));
        assert_eq!(reservation_snapshot(&forward_reservation), forward_before);
        assert_eq!(auth_lifecycle_state(&forward_database), "initializing");
        forward_stores
            .conversation
            .report()
            .await
            .expect("forward rejection keeps store healthy");
        forward_actor
            .shutdown()
            .await
            .expect("forward actor shutdown");

        let blocked_root = directory.path().join("blocked");
        let blocked_fixture = initialization_fixture("owner_01");
        let (blocked_actor, blocked_stores) = actor_and_stores(&blocked_root).await;
        let blocked_reservation = write_pre_source_reservation(
            &blocked_root,
            &blocked_fixture,
            &blocked_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        owner_file(&blocked_reservation.join("unknown"), b"preserve");
        let blocked_before = reservation_snapshot(&blocked_reservation);
        assert_eq!(
            blocked_actor
                .recover_initialization_pre_source()
                .await
                .expect("blocked typed rejection"),
            AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::UnrecognizedArtifacts
                )
            )
        );
        assert_eq!(reservation_snapshot(&blocked_reservation), blocked_before);
        blocked_stores
            .conversation
            .report()
            .await
            .expect("blocked rejection keeps store healthy");
        blocked_actor
            .shutdown()
            .await
            .expect("blocked actor shutdown");

        let cleanup_root = directory.path().join("cleanup");
        let cleanup_namespace = cleanup_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (cleanup_actor, cleanup_stores) = actor_and_stores(&cleanup_root).await;
        fs::create_dir(&cleanup_namespace).expect("cleanup namespace");
        fs::set_permissions(&cleanup_namespace, fs::Permissions::from_mode(0o700))
            .expect("cleanup namespace mode");
        assert_eq!(
            cleanup_actor
                .recover_initialization_pre_source()
                .await
                .expect("cleanup typed rejection"),
            AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::InconsistentDbFilesystem
                )
            )
        );
        assert_eq!(
            fs::read_dir(&cleanup_namespace)
                .expect("preserved cleanup namespace")
                .count(),
            0
        );
        cleanup_stores
            .conversation
            .report()
            .await
            .expect("cleanup rejection keeps store healthy");
        cleanup_actor
            .shutdown()
            .await
            .expect("cleanup actor shutdown");
    }

    #[tokio::test]
    async fn initialization_pre_source_recovery_faults_resume_from_exact_phase() {
        let directory = tempdir().expect("temporary parent");
        let cases = [
            (
                AuthInitializationPreSourceRecoveryTestFault::Metadata,
                AuthInitializationPreSourcePhase::StagedComplete,
                AuthInitializationPreSourceRecoveryOutcome::Prepared,
            ),
            (
                AuthInitializationPreSourceRecoveryTestFault::Staged,
                AuthInitializationPreSourcePhase::StagedComplete,
                AuthInitializationPreSourceRecoveryOutcome::Prepared,
            ),
            (
                AuthInitializationPreSourceRecoveryTestFault::Prepared,
                AuthInitializationPreSourcePhase::Prepared,
                AuthInitializationPreSourceRecoveryOutcome::AlreadyPrepared,
            ),
        ];

        for (index, (fault, expected_phase, expected_resume)) in cases.into_iter().enumerate() {
            let root = directory.path().join(format!("case-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let fixture = initialization_fixture("owner_01");
            let (actor, stores) = actor_and_stores(&root).await;
            let reservation = write_pre_source_reservation(
                &root,
                &fixture,
                &fixture.metadata,
                AuthInitializationPreSourcePhase::StagedComplete,
            );

            assert_eq!(
                actor
                    .start_recover_initialization_pre_source_with_fault(fault)
                    .expect("fault-injected recovery command")
                    .await
                    .unwrap_err(),
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                )),
                "{fault:?}"
            );
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
            actor.shutdown().await.expect("faulted actor shutdown");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("fault phase reconciliation"),
                AuthInitializationReconciliation::InitializePreSource {
                    phase: expected_phase,
                    recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
                },
                "{fault:?}"
            );
            assert_eq!(
                fresh_actor
                    .recover_initialization_pre_source()
                    .await
                    .expect("resumed recovery"),
                expected_resume,
                "{fault:?}"
            );
            assert!(reservation.join("prepared").is_file());
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            fresh_stores
                .conversation
                .report()
                .await
                .expect("resumed recovery keeps store healthy");
            fresh_actor
                .shutdown()
                .await
                .expect("fresh recovery actor shutdown");
        }
    }

    #[tokio::test]
    async fn initialization_source_durability_fence_faults_before_database_mutation() {
        let directory = tempdir().expect("temporary parent");
        for (index, fault) in [
            AuthInitializationSourceDurabilityTestFault::Metadata,
            AuthInitializationSourceDurabilityTestFault::Staged,
            AuthInitializationSourceDurabilityTestFault::Prepared,
        ]
        .into_iter()
        .enumerate()
        {
            let root = directory.path().join(format!("case-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let (actor, stores) = actor_and_stores(&root).await;
            assert_eq!(
                actor
                    .prepare_initialization(initialization_preparation("owner_01"))
                    .await
                    .expect("prepared initialization"),
                AuthInitializationPrepareOutcome::Prepared
            );
            let reservation = root
                .join(SECRET_DIRECTORY_NAME)
                .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
            let before = reservation_snapshot(&reservation);

            assert_eq!(
                actor
                    .start_commit_initialization_source_with_durability_fault(fault)
                    .expect("fault-injected source durability command")
                    .await
                    .unwrap_err(),
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                )),
                "{fault:?}"
            );
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            assert_eq!(
                reservation_snapshot(&reservation),
                before,
                "durability fence must not rewrite prepared evidence"
            );
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
            actor
                .shutdown()
                .await
                .expect("faulted source actor shutdown");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .commit_initialization_source()
                    .await
                    .expect("fresh source retry"),
                AuthInitializationSourceOutcome::Committed,
                "{fault:?}"
            );
            assert_eq!(auth_lifecycle_state(&database), "initializing");
            fresh_stores
                .conversation
                .report()
                .await
                .expect("fresh source retry keeps store healthy");
            fresh_actor
                .shutdown()
                .await
                .expect("fresh source actor shutdown");
        }
    }

    #[tokio::test]
    async fn initialization_pre_source_recovery_drift_preserves_evidence_and_poisons() {
        let directory = tempdir().expect("temporary parent");

        let source_root = directory.path().join("source-drift");
        let source_database = source_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let source_fixture = initialization_fixture("owner_01");
        let (source_actor, source_stores) = actor_and_stores(&source_root).await;
        let source_reservation = write_pre_source_reservation(
            &source_root,
            &source_fixture,
            &source_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let source_gate = ActorTestGate::new();
        let source_run = source_actor
            .start_recover_initialization_pre_source_with_before_mutation_gate(source_gate.clone())
            .expect("source-drift recovery");
        source_gate.wait_until_reached();
        commit_initializing_source(&source_database, &source_fixture);
        source_gate.resume();
        assert_eq!(
            source_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(!source_reservation.join("prepared").exists());
        assert_eq!(auth_lifecycle_state(&source_database), "initializing");
        assert!(matches!(
            source_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        source_actor
            .shutdown()
            .await
            .expect("source-drift actor shutdown");

        let race_root = directory.path().join("prepared-race");
        let race_fixture = initialization_fixture("owner_01");
        let (race_actor, race_stores) = actor_and_stores(&race_root).await;
        let race_reservation = write_pre_source_reservation(
            &race_root,
            &race_fixture,
            &race_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let race_gate = ActorTestGate::new();
        let race_run = race_actor
            .start_recover_initialization_pre_source_with_before_mutation_gate(race_gate.clone())
            .expect("prepared-race recovery");
        race_gate.wait_until_reached();
        owner_file(&race_reservation.join("prepared"), b"");
        race_gate.resume();
        assert_eq!(
            race_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(
            fs::read(race_reservation.join("prepared")).expect("raced prepared evidence"),
            b""
        );
        assert!(matches!(
            race_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        race_actor
            .shutdown()
            .await
            .expect("prepared-race actor shutdown");

        let hardlink_root = directory.path().join("hardlink-race");
        let hardlink_fixture = initialization_fixture("owner_01");
        let (hardlink_actor, hardlink_stores) = actor_and_stores(&hardlink_root).await;
        let hardlink_reservation = write_pre_source_reservation(
            &hardlink_root,
            &hardlink_fixture,
            &hardlink_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let hardlink_gate = ActorTestGate::new();
        let hardlink_run = hardlink_actor
            .start_recover_initialization_pre_source_with_before_mutation_gate(
                hardlink_gate.clone(),
            )
            .expect("hardlink-race recovery");
        hardlink_gate.wait_until_reached();
        fs::hard_link(
            hardlink_reservation.join("metadata"),
            hardlink_reservation.join("metadata-copy"),
        )
        .expect("raced metadata hardlink");
        hardlink_gate.resume();
        assert_eq!(
            hardlink_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact
            ))
        );
        assert!(hardlink_reservation.join("metadata-copy").is_file());
        assert_eq!(
            fs::symlink_metadata(hardlink_reservation.join("metadata"))
                .expect("hardlinked metadata")
                .nlink(),
            2
        );
        assert!(matches!(
            hardlink_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        hardlink_actor
            .shutdown()
            .await
            .expect("hardlink-race actor shutdown");

        let aba_root = directory.path().join("reservation-aba");
        let aba_fixture = initialization_fixture("owner_01");
        let (aba_actor, aba_stores) = actor_and_stores(&aba_root).await;
        let aba_reservation = write_pre_source_reservation(
            &aba_root,
            &aba_fixture,
            &aba_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let moved_reservation = aba_root.join("moved-transition-evidence");
        let aba_gate = ActorTestGate::new();
        let aba_run = aba_actor
            .start_recover_initialization_pre_source_with_before_mutation_gate(aba_gate.clone())
            .expect("reservation-ABA recovery");
        aba_gate.wait_until_reached();
        fs::rename(&aba_reservation, &moved_reservation).expect("move original reservation");
        let replacement = write_pre_source_reservation(
            &aba_root,
            &aba_fixture,
            &aba_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        aba_gate.resume();
        assert_eq!(
            aba_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(moved_reservation.is_dir());
        assert!(replacement.is_dir());
        assert!(!moved_reservation.join("prepared").exists());
        assert!(!replacement.join("prepared").exists());
        assert!(matches!(
            aba_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        aba_actor
            .shutdown()
            .await
            .expect("reservation-ABA actor shutdown");

        let post_root = directory.path().join("post-create-replacement");
        let post_fixture = initialization_fixture("owner_01");
        let (post_actor, post_stores) = actor_and_stores(&post_root).await;
        let post_reservation = write_pre_source_reservation(
            &post_root,
            &post_fixture,
            &post_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let post_gate = ActorTestGate::new();
        let post_run = post_actor
            .start_recover_initialization_pre_source_with_after_recovery_gate(post_gate.clone())
            .expect("post-create replacement recovery");
        post_gate.wait_until_reached();
        let preserved_prepared = post_reservation.join("prepared-preserved");
        fs::rename(post_reservation.join("prepared"), &preserved_prepared)
            .expect("preserve original prepared");
        owner_file(&post_reservation.join("prepared"), b"");
        post_gate.resume();
        assert_eq!(
            post_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(preserved_prepared.is_file());
        assert!(post_reservation.join("prepared").is_file());
        assert!(matches!(
            post_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        post_actor
            .shutdown()
            .await
            .expect("post-create actor shutdown");

        let post_source_root = directory.path().join("post-create-source-drift");
        let post_source_database = post_source_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let post_source_fixture = initialization_fixture("owner_01");
        let (post_source_actor, post_source_stores) = actor_and_stores(&post_source_root).await;
        let post_source_reservation = write_pre_source_reservation(
            &post_source_root,
            &post_source_fixture,
            &post_source_fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let post_source_gate = ActorTestGate::new();
        let post_source_run = post_source_actor
            .start_recover_initialization_pre_source_with_after_recovery_gate(
                post_source_gate.clone(),
            )
            .expect("post-create source-drift recovery");
        post_source_gate.wait_until_reached();
        commit_initializing_source(&post_source_database, &post_source_fixture);
        post_source_gate.resume();
        assert_eq!(
            post_source_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(post_source_reservation.join("prepared").is_file());
        assert_eq!(auth_lifecycle_state(&post_source_database), "initializing");
        assert!(matches!(
            post_source_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        post_source_actor
            .shutdown()
            .await
            .expect("post-source actor shutdown");
    }

    #[tokio::test]
    async fn dropped_pre_source_recovery_receiver_does_not_cancel_admitted_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        let reservation = write_pre_source_reservation(
            &root,
            &fixture,
            &fixture.metadata,
            AuthInitializationPreSourcePhase::StagedComplete,
        );
        let gate = ActorTestGate::new();
        let run = actor
            .start_recover_initialization_pre_source_with_gate(gate.clone())
            .expect("gated pre-source recovery");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();
        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("recovery waiter is cancelled")
                .is_cancelled()
        );
        gate.resume();

        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected actor error after receiver drop: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached recovery")
        .expect("prepared recovery readback");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            }
        );
        assert!(reservation.join("prepared").is_file());
        assert_eq!(
            actor
                .recover_initialization_pre_source()
                .await
                .expect("detached recovery replay"),
            AuthInitializationPreSourceRecoveryOutcome::AlreadyPrepared
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop after admission does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_pre_source_rollback_accepts_every_phase_and_replays_redacted() {
        let directory = tempdir().expect("temporary parent");
        let phases = [
            AuthInitializationPreSourcePhase::ReservationOnly,
            AuthInitializationPreSourcePhase::MetadataIncomplete,
            AuthInitializationPreSourcePhase::MetadataComplete,
            AuthInitializationPreSourcePhase::StagedIncomplete,
            AuthInitializationPreSourcePhase::StagedComplete,
            AuthInitializationPreSourcePhase::Prepared,
        ];

        for (index, phase) in phases.into_iter().enumerate() {
            let root = directory.path().join(format!("current-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let fixture = initialization_fixture("owner_01");
            let (actor, stores) = actor_and_stores(&root).await;
            let transition =
                write_pre_source_reservation(&root, &fixture, &fixture.metadata, phase);
            let cleanup = transition
                .parent()
                .expect("secret directory")
                .join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
            let recovery = if matches!(
                phase,
                AuthInitializationPreSourcePhase::StagedComplete
                    | AuthInitializationPreSourcePhase::Prepared
            ) {
                AuthInitializationRecovery::ResumeOrRollbackCandidate
            } else {
                AuthInitializationRecovery::RollbackOnlyCandidate
            };
            assert_eq!(
                actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("pre-source phase"),
                AuthInitializationReconciliation::InitializePreSource { phase, recovery }
            );

            let rolled_back = actor
                .rollback_initialization_pre_source()
                .await
                .expect("pre-source rollback");
            assert_eq!(rolled_back, AuthInitializationRollbackOutcome::RolledBack);
            assert!(!transition.exists(), "{phase:?}");
            assert!(!cleanup.exists(), "{phase:?}");
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            assert_eq!(
                actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("clean rollback readback"),
                AuthInitializationReconciliation::CleanUninitialized
            );
            let replay = actor
                .rollback_initialization_pre_source()
                .await
                .expect("clean rollback replay");
            assert_eq!(replay, AuthInitializationRollbackOutcome::AlreadyClean);
            let rendered = format!("{rolled_back:?} {replay:?}");
            for secret in [
                fixture.login_id,
                fixture.kid.as_str(),
                fixture.password_phc.as_str(),
                fixture.recovery_phc.as_str(),
            ] {
                assert!(!rendered.contains(secret), "{secret}");
            }
            let mut names: Vec<String> = fs::read_dir(root.join(SECRET_DIRECTORY_NAME))
                .expect("terminal secret directory")
                .map(|entry| {
                    entry
                        .expect("terminal secret entry")
                        .file_name()
                        .into_string()
                        .expect("canonical terminal name")
                })
                .collect();
            names.sort();
            assert_eq!(names, [AUTH_LOCK_FILE_NAME]);
            stores
                .conversation
                .report()
                .await
                .expect("rollback keeps store healthy");
            actor.shutdown().await.expect("joined rollback actor");
        }

        for (index, phase) in [
            AuthInitializationPreSourcePhase::MetadataComplete,
            AuthInitializationPreSourcePhase::StagedIncomplete,
            AuthInitializationPreSourcePhase::StagedComplete,
            AuthInitializationPreSourcePhase::Prepared,
        ]
        .into_iter()
        .enumerate()
        {
            let root = directory.path().join(format!("historical-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let fixture = initialization_fixture("owner_01");
            let historical = legacy_metadata(&fixture.metadata);
            let (actor, stores) = actor_and_stores(&root).await;
            let transition = write_pre_source_reservation(&root, &fixture, &historical, phase);
            assert_eq!(
                actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("historical pre-source phase"),
                AuthInitializationReconciliation::InitializePreSource {
                    phase,
                    recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                }
            );
            assert_eq!(
                actor
                    .rollback_initialization_pre_source()
                    .await
                    .expect("historical rollback"),
                AuthInitializationRollbackOutcome::RolledBack
            );
            assert!(!transition.exists());
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            stores
                .conversation
                .report()
                .await
                .expect("historical rollback keeps store healthy");
            actor
                .shutdown()
                .await
                .expect("joined historical rollback actor");
        }
    }

    #[tokio::test]
    async fn initialization_pre_source_rollback_faults_resume_from_exact_phase() {
        let directory = tempdir().expect("temporary parent");
        let cases = [
            (
                AuthInitializationRollbackTestFault::Prepared,
                AuthInitializationReconciliation::InitializePreSource {
                    phase: AuthInitializationPreSourcePhase::StagedComplete,
                    recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
                },
            ),
            (
                AuthInitializationRollbackTestFault::Staged,
                AuthInitializationReconciliation::InitializePreSource {
                    phase: AuthInitializationPreSourcePhase::MetadataComplete,
                    recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthInitializationRollbackTestFault::Metadata,
                AuthInitializationReconciliation::InitializePreSource {
                    phase: AuthInitializationPreSourcePhase::ReservationOnly,
                    recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthInitializationRollbackTestFault::Directory,
                AuthInitializationReconciliation::CleanUninitialized,
            ),
        ];

        for (index, (fault, expected_phase)) in cases.into_iter().enumerate() {
            let root = directory.path().join(format!("case-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let (actor, stores) = actor_and_stores(&root).await;
            assert_eq!(
                actor
                    .prepare_initialization(initialization_preparation("owner_01"))
                    .await
                    .expect("prepared initialization"),
                AuthInitializationPrepareOutcome::Prepared
            );
            assert_eq!(
                actor
                    .start_rollback_initialization_pre_source_with_fault(fault)
                    .expect("faulted rollback command")
                    .await
                    .unwrap_err(),
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            );
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
            actor.shutdown().await.expect("faulted actor shutdown");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("fault phase reconciliation"),
                expected_phase,
                "{fault:?}"
            );
            let resumed = fresh_actor
                .rollback_initialization_pre_source()
                .await
                .expect("resumed rollback");
            assert_eq!(
                resumed,
                if expected_phase == AuthInitializationReconciliation::CleanUninitialized {
                    AuthInitializationRollbackOutcome::AlreadyClean
                } else {
                    AuthInitializationRollbackOutcome::RolledBack
                },
                "{fault:?}"
            );
            assert_uninitialized_auth_source(&database);
            assert_eq!(auth_audit_shape(&database), (0, None));
            fresh_stores
                .conversation
                .report()
                .await
                .expect("resumed rollback keeps store healthy");
            fresh_actor
                .shutdown()
                .await
                .expect("fresh rollback actor shutdown");
        }
    }

    #[tokio::test]
    async fn initialization_pre_source_rollback_accepts_confirmed_no_commit() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        assert_eq!(
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("confirmed-no-commit preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .start_commit_initialization_source_with_fault(
                    AuthInitializationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                )
                .expect("faulted source command")
                .await
                .expect("confirmed no-commit outcome"),
            AuthInitializationSourceOutcome::ConfirmedNotCommitted
        );
        assert_eq!(
            actor
                .rollback_initialization_pre_source()
                .await
                .expect("rollback after confirmed no-commit"),
            AuthInitializationRollbackOutcome::RolledBack
        );
        assert_uninitialized_auth_source(&database);
        assert_eq!(auth_audit_shape(&database), (0, None));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("clean readback"),
            AuthInitializationReconciliation::CleanUninitialized
        );
        stores
            .conversation
            .report()
            .await
            .expect("confirmed-no-commit rollback keeps store healthy");
        actor.shutdown().await.expect("joined rollback actor");
    }

    #[tokio::test]
    async fn initialization_pre_source_rollback_rejects_ineligible_state_without_mutation() {
        let directory = tempdir().expect("temporary parent");

        let clean_root = directory.path().join("clean");
        let (clean_actor, clean_stores) = actor_and_stores(&clean_root).await;
        assert_eq!(
            clean_actor
                .rollback_initialization_pre_source()
                .await
                .expect("clean rollback"),
            AuthInitializationRollbackOutcome::AlreadyClean
        );
        clean_stores
            .conversation
            .report()
            .await
            .expect("clean replay keeps store healthy");
        clean_actor.shutdown().await.expect("clean actor shutdown");

        let cleanup_root = directory.path().join("cleanup-namespace");
        let cleanup_namespace = cleanup_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (cleanup_actor, cleanup_stores) = actor_and_stores(&cleanup_root).await;
        fs::create_dir(&cleanup_namespace).expect("preexisting cleanup namespace");
        fs::set_permissions(&cleanup_namespace, fs::Permissions::from_mode(0o700))
            .expect("cleanup namespace mode");
        let cleanup = cleanup_actor
            .rollback_initialization_pre_source()
            .await
            .expect("cleanup namespace rollback rejection");
        assert_eq!(
            cleanup,
            AuthInitializationRollbackOutcome::NotRollbackable(
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::InconsistentDbFilesystem
                )
            )
        );
        assert_eq!(
            fs::read_dir(&cleanup_namespace)
                .expect("preserved cleanup namespace")
                .count(),
            0
        );
        cleanup_stores
            .conversation
            .report()
            .await
            .expect("cleanup namespace rejection keeps store healthy");
        cleanup_actor
            .shutdown()
            .await
            .expect("cleanup namespace actor shutdown");

        let forward_root = directory.path().join("forward");
        let forward_database = forward_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let forward_transition = forward_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (forward_actor, forward_stores) = actor_and_stores(&forward_root).await;
        assert_eq!(
            forward_actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("forward preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        assert_eq!(
            forward_actor
                .commit_initialization_source()
                .await
                .expect("forward source"),
            AuthInitializationSourceOutcome::Committed
        );
        let forward = forward_actor
            .rollback_initialization_pre_source()
            .await
            .expect("forward rollback rejection");
        assert!(matches!(
            forward,
            AuthInitializationRollbackOutcome::NotRollbackable(
                AuthInitializationReconciliation::InitializeForwardOnly(_)
            )
        ));
        assert_eq!(
            format!("{forward:?}"),
            "AuthInitializationRollbackOutcome::NotRollbackable([REDACTED])"
        );
        assert!(forward_transition.is_dir());
        assert_eq!(auth_lifecycle_state(&forward_database), "initializing");
        forward_stores
            .conversation
            .report()
            .await
            .expect("forward rejection keeps store healthy");
        forward_actor
            .shutdown()
            .await
            .expect("forward actor shutdown");

        let blocked_root = directory.path().join("blocked");
        let blocked_transition = blocked_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (blocked_actor, blocked_stores) = actor_and_stores(&blocked_root).await;
        assert_eq!(
            blocked_actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("blocked preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        owner_file(&blocked_transition.join("unknown"), b"preserve");
        let blocked = blocked_actor
            .rollback_initialization_pre_source()
            .await
            .expect("blocked rollback rejection");
        assert_eq!(
            blocked,
            AuthInitializationRollbackOutcome::NotRollbackable(
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::UnrecognizedArtifacts
                )
            )
        );
        assert_eq!(
            format!("{blocked:?}"),
            "AuthInitializationRollbackOutcome::NotRollbackable([REDACTED])"
        );
        assert_eq!(
            fs::read(blocked_transition.join("unknown")).expect("unknown evidence"),
            b"preserve"
        );
        assert!(blocked_transition.join("prepared").is_file());
        blocked_stores
            .conversation
            .report()
            .await
            .expect("blocked rejection keeps store healthy");
        blocked_actor
            .shutdown()
            .await
            .expect("blocked actor shutdown");
    }

    #[tokio::test]
    async fn initialization_pre_source_rollback_drift_preserves_evidence_and_poisons() {
        let directory = tempdir().expect("temporary parent");

        let source_root = directory.path().join("source-drift");
        let source_database = source_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let source_transition = source_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let source_fixture = initialization_fixture("owner_01");
        let (source_actor, source_stores) = actor_and_stores(&source_root).await;
        write_prepared_reservation(&source_root, &source_fixture, &source_fixture.metadata);
        let source_gate = ActorTestGate::new();
        let source_run = source_actor
            .start_rollback_initialization_pre_source_with_before_mutation_gate(source_gate.clone())
            .expect("source-drift rollback");
        source_gate.wait_until_reached();
        commit_initializing_source(&source_database, &source_fixture);
        source_gate.resume();

        assert_eq!(
            source_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(source_transition.join("prepared").is_file());
        assert_eq!(auth_lifecycle_state(&source_database), "initializing");
        assert!(matches!(
            source_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        source_actor
            .shutdown()
            .await
            .expect("source-drift actor shutdown");

        let aba_root = directory.path().join("reservation-aba");
        let aba_transition = aba_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let moved_transition = aba_root.join("moved-transition-evidence");
        let aba_fixture = initialization_fixture("owner_01");
        let (aba_actor, aba_stores) = actor_and_stores(&aba_root).await;
        assert_eq!(
            aba_actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("ABA preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        let aba_gate = ActorTestGate::new();
        let aba_run = aba_actor
            .start_rollback_initialization_pre_source_with_before_mutation_gate(aba_gate.clone())
            .expect("ABA rollback");
        aba_gate.wait_until_reached();
        fs::rename(&aba_transition, &moved_transition).expect("move original reservation");
        fs::create_dir(&aba_transition).expect("replacement reservation");
        fs::set_permissions(&aba_transition, fs::Permissions::from_mode(0o700))
            .expect("replacement reservation mode");
        owner_file(
            &aba_transition.join("metadata"),
            aba_fixture.metadata.expose_secret(),
        );
        owner_file(
            &aba_transition.join("staged-keyring"),
            aba_fixture.staged.expose_secret(),
        );
        owner_file(&aba_transition.join("prepared"), b"");
        aba_gate.resume();

        assert_eq!(
            aba_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(aba_transition.join("prepared").is_file());
        assert!(moved_transition.join("prepared").is_file());
        assert!(matches!(
            aba_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        aba_actor.shutdown().await.expect("ABA actor shutdown");

        let hardlink_root = directory.path().join("hardlink-drift");
        let hardlink_transition = hardlink_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (hardlink_actor, hardlink_stores) = actor_and_stores(&hardlink_root).await;
        assert_eq!(
            hardlink_actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("hardlink preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        let hardlink_gate = ActorTestGate::new();
        let hardlink_run = hardlink_actor
            .start_rollback_initialization_pre_source_with_before_mutation_gate(
                hardlink_gate.clone(),
            )
            .expect("hardlink rollback");
        hardlink_gate.wait_until_reached();
        fs::hard_link(
            hardlink_transition.join("prepared"),
            hardlink_root
                .join(SECRET_DIRECTORY_NAME)
                .join("prepared-alias"),
        )
        .expect("insert hardlink");
        hardlink_gate.resume();

        assert!(matches!(
            hardlink_run.await,
            Err(AuthMaintenanceActorError::Binding(
                AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact | SecretFsError::ArtifactChanged
                )
            ))
        ));
        assert!(hardlink_transition.join("prepared").is_file());
        assert!(matches!(
            hardlink_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        hardlink_actor
            .shutdown()
            .await
            .expect("hardlink actor shutdown");

        let post_root = directory.path().join("post-drift");
        let post_database = post_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let post_fixture = initialization_fixture("owner_01");
        let (post_actor, post_stores) = actor_and_stores(&post_root).await;
        write_prepared_reservation(&post_root, &post_fixture, &post_fixture.metadata);
        let post_gate = ActorTestGate::new();
        let post_run = post_actor
            .start_rollback_initialization_pre_source_with_after_rollback_gate(post_gate.clone())
            .expect("post-drift rollback");
        post_gate.wait_until_reached();
        commit_initializing_source(&post_database, &post_fixture);
        post_gate.resume();

        assert_eq!(
            post_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(auth_lifecycle_state(&post_database), "initializing");
        assert!(
            !post_root
                .join(SECRET_DIRECTORY_NAME)
                .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111")
                .exists()
        );
        assert!(matches!(
            post_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        post_actor
            .shutdown()
            .await
            .expect("post-drift actor shutdown");
    }

    #[tokio::test]
    async fn dropped_rollback_receiver_does_not_cancel_actor_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        assert_eq!(
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("rollback preparation"),
            AuthInitializationPrepareOutcome::Prepared
        );
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_initialization_pre_source_with_gate(gate.clone())
            .expect("gated rollback");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();
        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("rollback waiter cancelled")
                .is_cancelled()
        );
        gate.resume();

        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected post-drop rollback error: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached rollback")
        .expect("post-rollback reconciliation");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::CleanUninitialized
        );
        assert_uninitialized_auth_source(&database);
        assert_eq!(auth_audit_shape(&database), (0, None));
        assert_eq!(
            actor
                .rollback_initialization_pre_source()
                .await
                .expect("rollback replay"),
            AuthInitializationRollbackOutcome::AlreadyClean
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop keeps store healthy");
        actor.shutdown().await.expect("joined rollback shutdown");
    }

    #[tokio::test]
    async fn initialization_source_commit_is_exact_replayable_and_redacted() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        assert_eq!(
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("prepared initialization"),
            AuthInitializationPrepareOutcome::Prepared
        );

        let committed = actor
            .commit_initialization_source()
            .await
            .expect("exact initialization source commit");
        assert_eq!(committed, AuthInitializationSourceOutcome::Committed);
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("post-source reconciliation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp
            )
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            persisted_legacy_policy_provenance(&database),
            NO_BLOCKLIST_CHECK_SENTINEL
        );

        let replay = actor
            .commit_initialization_source()
            .await
            .expect("same-source replay");
        assert_eq!(replay, AuthInitializationSourceOutcome::AlreadyCommitted);
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));

        let rendered = format!("{committed:?} {replay:?}");
        for secret in [
            fixture.login_id,
            fixture.kid.as_str(),
            fixture.password_phc.as_str(),
            fixture.recovery_phc.as_str(),
        ] {
            assert!(!rendered.contains(secret), "{secret}");
        }
        stores
            .conversation
            .report()
            .await
            .expect("commit and replay keep store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn historical_and_not_prepared_source_commands_are_typed_no_mutation() {
        let directory = tempdir().expect("temporary parent");
        let clean_root = directory.path().join("clean-instance");
        let clean_database = clean_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let (clean_actor, clean_stores) = actor_and_stores(&clean_root).await;
        let clean = clean_actor
            .commit_initialization_source()
            .await
            .expect("clean no-source outcome");
        assert_eq!(
            clean,
            AuthInitializationSourceOutcome::NotPrepared(
                AuthInitializationReconciliation::CleanUninitialized
            )
        );
        assert_eq!(
            format!("{clean:?}"),
            "AuthInitializationSourceOutcome::NotPrepared([REDACTED])"
        );
        assert_uninitialized_auth_source(&clean_database);
        clean_stores
            .conversation
            .report()
            .await
            .expect("clean no-source outcome does not poison");
        clean_actor.shutdown().await.expect("clean actor shutdown");

        let historical_root = directory.path().join("historical-instance");
        let historical_database = historical_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (historical_actor, historical_stores) = actor_and_stores(&historical_root).await;
        let historical = legacy_metadata(&fixture.metadata);
        let reservation = write_prepared_reservation(&historical_root, &fixture, &historical);

        let outcome = historical_actor
            .commit_initialization_source()
            .await
            .expect("historical prepared outcome");
        assert_eq!(outcome, AuthInitializationSourceOutcome::LegacyPrepared);
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("historical metadata retained"),
            historical.expose_secret()
        );
        assert_uninitialized_auth_source(&historical_database);
        historical_stores
            .conversation
            .report()
            .await
            .expect("historical prepared outcome does not poison");
        historical_actor
            .shutdown()
            .await
            .expect("historical actor shutdown");
    }

    #[tokio::test]
    async fn database_race_is_typed_precondition_change_without_duplicate_source() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        let gate = ActorTestGate::new();
        let run = actor
            .start_commit_initialization_source_with_pre_mutation_gate(gate.clone())
            .expect("gated source commit");
        gate.wait_until_reached();

        let raced_fixture = initialization_fixture("owner_02");
        commit_initializing_source(&database, &raced_fixture);
        gate.resume();

        assert_eq!(
            run.await.expect("typed source race"),
            AuthInitializationSourceOutcome::PreconditionChanged
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("mismatched source remains observable"),
            AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem
            )
        );
        stores
            .conversation
            .report()
            .await
            .expect("valid changed precondition does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn exact_source_race_is_already_committed_without_duplicate_audit() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        let gate = ActorTestGate::new();
        let run = actor
            .start_commit_initialization_source_with_pre_mutation_gate(gate.clone())
            .expect("gated source commit");
        gate.wait_until_reached();

        commit_initializing_source(&database, &fixture);
        gate.resume();

        assert_eq!(
            run.await.expect("exact raced source replay"),
            AuthInitializationSourceOutcome::AlreadyCommitted
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("exact raced source reconciliation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp
            )
        );
        stores
            .conversation
            .report()
            .await
            .expect("exact raced source keeps store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn response_loss_and_failed_commit_have_exact_recoverable_outcomes() {
        let directory = tempdir().expect("temporary parent");
        let response_loss_root = directory.path().join("response-loss-instance");
        let (response_loss_actor, response_loss_stores) =
            actor_and_stores(&response_loss_root).await;
        response_loss_actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("response-loss preparation");
        assert_eq!(
            response_loss_actor
                .start_commit_initialization_source_with_fault(
                    AuthInitializationSourceMutationTestFault::AfterCommitResponseLoss,
                )
                .expect("response-loss source command")
                .await
                .expect("response-loss committed readback"),
            AuthInitializationSourceOutcome::Committed
        );
        assert_eq!(
            response_loss_actor
                .inspect_initialization_reconciliation()
                .await
                .expect("response-loss reconciliation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp
            )
        );
        response_loss_stores
            .conversation
            .report()
            .await
            .expect("response-loss classification keeps store healthy");
        response_loss_actor
            .shutdown()
            .await
            .expect("response-loss actor shutdown");

        let failed_root = directory.path().join("failed-commit-instance");
        let failed_database = failed_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let (failed_actor, failed_stores) = actor_and_stores(&failed_root).await;
        failed_actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("failed-commit preparation");
        assert_eq!(
            failed_actor
                .start_commit_initialization_source_with_fault(
                    AuthInitializationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                )
                .expect("failed source command")
                .await
                .expect("confirmed no-commit classification"),
            AuthInitializationSourceOutcome::ConfirmedNotCommitted
        );
        assert_uninitialized_auth_source(&failed_database);
        assert_eq!(
            failed_actor
                .inspect_initialization_reconciliation()
                .await
                .expect("prepared state survives failed commit"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            }
        );
        assert_eq!(
            failed_actor
                .commit_initialization_source()
                .await
                .expect("retry after confirmed no-commit"),
            AuthInitializationSourceOutcome::Committed
        );
        failed_stores
            .conversation
            .report()
            .await
            .expect("confirmed no-commit retry keeps store healthy");
        failed_actor
            .shutdown()
            .await
            .expect("failed-commit actor shutdown");
    }

    #[tokio::test]
    async fn dropped_source_receiver_does_not_cancel_actor_commit() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        let gate = ActorTestGate::new();
        let run = actor
            .start_commit_initialization_source_with_gate(gate.clone())
            .expect("gated source commit");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();

        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("source waiter is cancelled")
                .is_cancelled()
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        gate.resume();

        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected actor error after receiver drop: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached source commit")
        .expect("source reconciliation");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp
            )
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn post_commit_filesystem_drift_poisons_and_keeps_lock_until_shutdown() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let gate = ActorTestGate::new();
        let run = actor
            .start_commit_initialization_source_with_post_mutation_gate(gate.clone())
            .expect("post-commit gated source command");
        gate.wait_until_reached();

        owner_file(&reservation.join("metadata"), b"POV");
        gate.resume();

        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("drift evidence retained"),
            b"POV"
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            actor.commit_initialization_source().await.unwrap_err(),
            AuthMaintenanceActorError::Poisoned
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn initialization_active_key_install_is_exact_durable_replayable_and_redacted() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let install =
            secrets.join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp");
        let reservation =
            secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        assert_eq!(
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("prepared initialization"),
            AuthInitializationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_initialization_source()
                .await
                .expect("committed source"),
            AuthInitializationSourceOutcome::Committed
        );

        let installed = actor
            .install_initialization_active_key()
            .await
            .expect("installed active key");
        assert_eq!(
            installed,
            AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
        assert_eq!(
            fs::read(&active).expect("active key bytes"),
            fixture.staged.expose_secret()
        );
        let active_metadata = fs::symlink_metadata(&active).expect("active metadata");
        assert_eq!(active_metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(active_metadata.nlink(), 1);
        assert!(!install.exists());
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("metadata retained"),
            fixture.metadata.expose_secret()
        );
        assert_eq!(
            fs::read(reservation.join("staged-keyring")).expect("stage retained"),
            fixture.staged.expose_secret()
        );
        assert_eq!(
            fs::read(reservation.join("prepared")).expect("prepared retained"),
            b""
        );
        assert_eq!(auth_lifecycle_state(&database), "initializing");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("post-install reconciliation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingFinalDbCas
            )
        );

        let active_inode = fs::symlink_metadata(&active)
            .expect("active inode before replay")
            .ino();
        let replay = actor
            .install_initialization_active_key()
            .await
            .expect("durable replay");
        assert_eq!(
            replay,
            AuthInitializationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode after replay")
                .ino(),
            active_inode
        );
        assert_eq!(auth_lifecycle_state(&database), "initializing");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        let rendered = format!("{installed:?} {replay:?}");
        for secret in [
            fixture.login_id,
            fixture.kid.as_str(),
            fixture.password_phc.as_str(),
            fixture.recovery_phc.as_str(),
        ] {
            assert!(!rendered.contains(secret), "{secret}");
        }
        stores
            .conversation
            .report()
            .await
            .expect("install and replay keep store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_active_key_install_recovers_prefix_exact_and_historical_source() {
        let directory = tempdir().expect("temporary parent");
        let staged = initialization_fixture("owner_01")
            .staged
            .expose_secret()
            .to_vec();
        let prefix = staged[..staged.len() - 1].to_vec();
        for (index, temp_bytes) in [Vec::new(), prefix, staged].into_iter().enumerate() {
            let root = directory.path().join(format!("resume-{index}"));
            let secrets = root.join(SECRET_DIRECTORY_NAME);
            let install =
                secrets.join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp");
            let fixture = initialization_fixture("owner_01");
            let (actor, stores) = actor_and_stores(&root).await;
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("prepared initialization");
            actor
                .commit_initialization_source()
                .await
                .expect("committed source");
            owner_file(&install, &temp_bytes);

            assert_eq!(
                actor
                    .install_initialization_active_key()
                    .await
                    .expect("recovered install phase"),
                AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
            );
            assert_eq!(
                fs::read(secrets.join("auth-keyring.v1")).expect("active key"),
                fixture.staged.expose_secret()
            );
            assert!(!install.exists());
            stores
                .conversation
                .report()
                .await
                .expect("recovery keeps store healthy");
            actor.shutdown().await.expect("resume actor shutdown");
        }

        let historical_root = directory.path().join("historical");
        let historical_database = historical_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (historical_actor, historical_stores) = actor_and_stores(&historical_root).await;
        let historical = legacy_metadata(&fixture.metadata);
        write_prepared_reservation(&historical_root, &fixture, &historical);
        commit_initializing_source_with_provenance(
            &historical_database,
            &fixture,
            &legacy_policy_provenance(),
        );
        assert_eq!(
            historical_actor
                .install_initialization_active_key()
                .await
                .expect("historical source completes forward"),
            AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
        assert_eq!(auth_lifecycle_state(&historical_database), "initializing");
        historical_stores
            .conversation
            .report()
            .await
            .expect("historical forward install keeps store healthy");
        historical_actor
            .shutdown()
            .await
            .expect("historical actor shutdown");
    }

    #[tokio::test]
    async fn initialization_active_key_install_rejects_pre_source_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");

        let outcome = actor
            .install_initialization_active_key()
            .await
            .expect("typed pre-source outcome");
        assert_eq!(
            outcome,
            AuthInitializationActiveKeyInstallOutcome::NotInstallable(
                AuthInitializationReconciliation::InitializePreSource {
                    phase: AuthInitializationPreSourcePhase::Prepared,
                    recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
                }
            )
        );
        assert_eq!(
            format!("{outcome:?}"),
            "AuthInitializationActiveKeyInstallOutcome::NotInstallable([REDACTED])"
        );
        assert!(!secrets.join("auth-keyring.v1").exists());
        assert!(
            !secrets
                .join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp")
                .exists()
        );
        stores
            .conversation
            .report()
            .await
            .expect("typed pre-source outcome does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_active_key_install_preserves_non_prefix_temp_as_typed_blocker() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let install = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        actor
            .commit_initialization_source()
            .await
            .expect("committed source");
        owner_file(&install, b"not-a-staged-prefix");

        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("typed blocked install"),
            AuthInitializationActiveKeyInstallOutcome::NotInstallable(
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::InconsistentDbFilesystem
                )
            )
        );
        assert_eq!(
            fs::read(&install).expect("invalid temp retained"),
            b"not-a-staged-prefix"
        );
        stores
            .conversation
            .report()
            .await
            .expect("typed blocker does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_active_key_install_faults_preserve_each_durable_phase_and_poison() {
        let directory = tempdir().expect("temporary parent");
        for (index, fault) in [
            AuthInitializationActiveKeyInstallTestFault::PrefixRemoved,
            AuthInitializationActiveKeyInstallTestFault::InstallTempDurable,
            AuthInitializationActiveKeyInstallTestFault::PublishDurable,
        ]
        .into_iter()
        .enumerate()
        {
            let root = directory.path().join(format!("fault-{index}"));
            let secrets = root.join(SECRET_DIRECTORY_NAME);
            let install =
                secrets.join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp");
            let active = secrets.join("auth-keyring.v1");
            let fixture = initialization_fixture("owner_01");
            let (actor, stores) = actor_and_stores(&root).await;
            actor
                .prepare_initialization(initialization_preparation("owner_01"))
                .await
                .expect("prepared initialization");
            actor
                .commit_initialization_source()
                .await
                .expect("committed source");
            if fault == AuthInitializationActiveKeyInstallTestFault::PrefixRemoved {
                owner_file(&install, b"");
            }

            assert_eq!(
                actor
                    .start_install_initialization_active_key_with_fault(fault)
                    .expect("faulted install command")
                    .await
                    .unwrap_err(),
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            );
            match fault {
                AuthInitializationActiveKeyInstallTestFault::PrefixRemoved => {
                    assert!(!install.exists());
                    assert!(!active.exists());
                }
                AuthInitializationActiveKeyInstallTestFault::InstallTempDurable => {
                    assert_eq!(
                        fs::read(&install).expect("durable install temp"),
                        fixture.staged.expose_secret()
                    );
                    assert!(!active.exists());
                }
                AuthInitializationActiveKeyInstallTestFault::PublishDurable => {
                    assert!(!install.exists());
                    assert_eq!(
                        fs::read(&active).expect("durable active key"),
                        fixture.staged.expose_secret()
                    );
                }
            }
            assert_eq!(
                auth_lifecycle_state(&root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3")),
                "initializing"
            );
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
            actor.shutdown().await.expect("joined poisoned shutdown");
        }
    }

    #[tokio::test]
    async fn initialization_active_key_publish_never_replaces_raced_destination() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let install =
            secrets.join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        actor
            .commit_initialization_source()
            .await
            .expect("committed source");
        let gate = ActorTestGate::new();
        let run = actor
            .start_install_initialization_active_key_with_before_publish_gate(gate.clone())
            .expect("gated install command");
        gate.wait_until_reached();

        owner_file(&active, b"do-not-clobber");
        gate.resume();

        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(
            fs::read(&active).expect("raced destination retained"),
            b"do-not-clobber"
        );
        assert_eq!(
            fs::read(&install).expect("install evidence retained"),
            fixture.staged.expose_secret()
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn post_install_active_drift_poisons_and_preserves_evidence() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        actor
            .commit_initialization_source()
            .await
            .expect("committed source");
        let gate = ActorTestGate::new();
        let run = actor
            .start_install_initialization_active_key_with_after_publish_gate(gate.clone())
            .expect("post-publish gated command");
        gate.wait_until_reached();

        owner_file(&active, b"POV");
        gate.resume();

        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(fs::read(&active).expect("drift evidence retained"), b"POV");
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn dropped_active_key_install_receiver_does_not_cancel_actor_work() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        actor
            .commit_initialization_source()
            .await
            .expect("committed source");
        let gate = ActorTestGate::new();
        let run = actor
            .start_install_initialization_active_key_with_gate(gate.clone())
            .expect("gated install command");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();
        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("install waiter cancelled")
                .is_cancelled()
        );
        gate.resume();

        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected post-drop actor error: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached install")
        .expect("post-install reconciliation");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingFinalDbCas
            )
        );
        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("replay after receiver drop"),
            AuthInitializationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop keeps store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_final_lifecycle_is_exact_replayable_and_redacted() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let reservation =
            secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_installed_active_key(&actor).await;
        let active_inode = fs::symlink_metadata(&active)
            .expect("active inode before final CAS")
            .ino();

        let activated = actor
            .commit_initialization_final_lifecycle()
            .await
            .expect("committed final lifecycle");
        assert_eq!(
            activated,
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        let lifecycle = RawConnection::open(&database)
            .expect("read active lifecycle")
            .query_row(
                "SELECT
                    state, state_revision, expected_kid, transition_kind,
                    transition_id, keyring_version, updated_at_micros
                 FROM auth_key_lifecycle
                 WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .expect("active lifecycle row");
        assert_eq!(
            lifecycle,
            (
                "active".to_owned(),
                2,
                Some(fixture.kid.clone()),
                None,
                None,
                Some(1),
                SOURCE_AT_MICROS,
            )
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("active reconciliation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingCleanupRename
            )
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode after final CAS")
                .ino(),
            active_inode
        );
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("metadata retained"),
            fixture.metadata.expose_secret()
        );
        assert_eq!(
            fs::read(reservation.join("staged-keyring")).expect("stage retained"),
            fixture.staged.expose_secret()
        );
        assert!(reservation.join("prepared").exists());

        let replay = actor
            .commit_initialization_final_lifecycle()
            .await
            .expect("final lifecycle replay");
        assert_eq!(
            replay,
            AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode after replay")
                .ino(),
            active_inode
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("install after activation is typed"),
            AuthInitializationActiveKeyInstallOutcome::NotInstallable(
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupRename
                )
            )
        );
        let rendered = format!("{activated:?} {replay:?}");
        for secret in [
            fixture.login_id,
            fixture.kid.as_str(),
            fixture.password_phc.as_str(),
            fixture.recovery_phc.as_str(),
        ] {
            assert!(!rendered.contains(secret), "{secret}");
        }
        stores
            .conversation
            .report()
            .await
            .expect("final lifecycle and replay keep store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_final_lifecycle_rejects_pre_install_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        actor
            .prepare_initialization(initialization_preparation("owner_01"))
            .await
            .expect("prepared initialization");
        actor
            .commit_initialization_source()
            .await
            .expect("committed source");

        let outcome = actor
            .commit_initialization_final_lifecycle()
            .await
            .expect("typed pre-install outcome");
        assert_eq!(
            outcome,
            AuthInitializationFinalLifecycleOutcome::NotActivatable(
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingInstallTemp
                )
            )
        );
        assert_eq!(
            format!("{outcome:?}"),
            "AuthInitializationFinalLifecycleOutcome::NotActivatable([REDACTED])"
        );
        assert_eq!(auth_lifecycle_state(&database), "initializing");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        stores
            .conversation
            .report()
            .await
            .expect("typed pre-install outcome stays healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_final_lifecycle_accepts_historical_canonical_source() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        let historical = legacy_metadata(&fixture.metadata);
        write_prepared_reservation(&root, &fixture, &historical);
        commit_initializing_source_with_provenance(
            &database,
            &fixture,
            &legacy_policy_provenance(),
        );
        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("historical active key install"),
            AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );

        assert_eq!(
            actor
                .commit_initialization_final_lifecycle()
                .await
                .expect("historical source final lifecycle"),
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        assert_eq!(auth_lifecycle_state(&database), "active");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        stores
            .conversation
            .report()
            .await
            .expect("historical final lifecycle keeps store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn final_lifecycle_response_loss_and_failed_commit_have_recoverable_outcomes() {
        let directory = tempdir().expect("temporary parent");

        let committed_root = directory.path().join("response-loss");
        let committed_database = committed_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let (committed_actor, committed_stores) = actor_and_stores(&committed_root).await;
        advance_initialization_to_installed_active_key(&committed_actor).await;
        assert_eq!(
            committed_actor
                .start_commit_initialization_final_lifecycle_with_fault(
                    AuthInitializationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                )
                .expect("response-loss final command")
                .await
                .expect("response loss classified"),
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        assert_eq!(auth_lifecycle_state(&committed_database), "active");
        committed_stores
            .conversation
            .report()
            .await
            .expect("classified response loss stays healthy");
        committed_actor
            .shutdown()
            .await
            .expect("response-loss actor shutdown");

        let failed_root = directory.path().join("failed-commit");
        let failed_database = failed_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let (failed_actor, failed_stores) = actor_and_stores(&failed_root).await;
        advance_initialization_to_installed_active_key(&failed_actor).await;
        assert_eq!(
            failed_actor
                .start_commit_initialization_final_lifecycle_with_fault(
                    AuthInitializationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                )
                .expect("failed final command")
                .await
                .expect("failed commit classified"),
            AuthInitializationFinalLifecycleOutcome::ConfirmedNotActivated
        );
        assert_eq!(auth_lifecycle_state(&failed_database), "initializing");
        assert_eq!(
            failed_actor
                .commit_initialization_final_lifecycle()
                .await
                .expect("final lifecycle retry"),
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        assert_eq!(auth_lifecycle_state(&failed_database), "active");
        failed_stores
            .conversation
            .report()
            .await
            .expect("failed commit retry stays healthy");
        failed_actor
            .shutdown()
            .await
            .expect("failed-commit actor shutdown");
    }

    #[tokio::test]
    async fn exact_external_final_lifecycle_race_is_idempotent_replay() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_installed_active_key(&actor).await;
        let active_inode = fs::symlink_metadata(&active).expect("active inode").ino();
        let gate = ActorTestGate::new();
        let run = actor
            .start_commit_initialization_final_lifecycle_with_pre_mutation_gate(gate.clone())
            .expect("gated final lifecycle");
        gate.wait_until_reached();
        RawConnection::open(&database)
            .expect("external exact final writer")
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'active',
                     state_revision = 2,
                     transition_kind = NULL,
                     transition_id = NULL
                 WHERE singleton = 1",
                [],
            )
            .expect("external exact final lifecycle");
        gate.resume();

        assert_eq!(
            run.await.expect("exact final race"),
            AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup
        );
        assert_eq!(auth_lifecycle_state(&database), "active");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode after race")
                .ino(),
            active_inode
        );
        stores
            .conversation
            .report()
            .await
            .expect("exact race stays healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn final_lifecycle_source_race_and_post_commit_filesystem_drift_poison() {
        let directory = tempdir().expect("temporary parent");

        let pre_drift_root = directory.path().join("pre-mutation-filesystem-drift");
        let pre_drift_database = pre_drift_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let pre_drift_active = pre_drift_root
            .join(SECRET_DIRECTORY_NAME)
            .join("auth-keyring.v1");
        let pre_drift_reservation = pre_drift_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (pre_drift_actor, pre_drift_stores) = actor_and_stores(&pre_drift_root).await;
        advance_initialization_to_installed_active_key(&pre_drift_actor).await;
        let gate = ActorTestGate::new();
        let run = pre_drift_actor
            .start_commit_initialization_final_lifecycle_with_pre_mutation_gate(gate.clone())
            .expect("pre-mutation gated final command");
        gate.wait_until_reached();
        owner_file(&pre_drift_active, b"POV-before");
        gate.resume();
        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(auth_lifecycle_state(&pre_drift_database), "initializing");
        assert_eq!(
            fs::read(&pre_drift_active).expect("pre-mutation drift retained"),
            b"POV-before"
        );
        assert!(pre_drift_reservation.exists());
        assert!(matches!(
            pre_drift_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        pre_drift_actor
            .shutdown()
            .await
            .expect("pre-mutation drift actor shutdown");

        let source_race_root = directory.path().join("source-race");
        let source_race_database = source_race_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let source_race_reservation = source_race_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (source_race_actor, source_race_stores) = actor_and_stores(&source_race_root).await;
        advance_initialization_to_installed_active_key(&source_race_actor).await;
        let gate = ActorTestGate::new();
        let run = source_race_actor
            .start_commit_initialization_final_lifecycle_with_pre_mutation_gate(gate.clone())
            .expect("source-race final command");
        gate.wait_until_reached();
        RawConnection::open(&source_race_database)
            .expect("source drift writer")
            .execute(
                "UPDATE auth_password_credentials
                 SET credential_revision = 2,
                     updated_at_micros = updated_at_micros + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("source drift");
        gate.resume();
        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        assert_eq!(auth_lifecycle_state(&source_race_database), "initializing");
        assert!(source_race_reservation.exists());
        assert!(matches!(
            source_race_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        source_race_actor
            .shutdown()
            .await
            .expect("source-race actor shutdown");

        let drift_root = directory.path().join("filesystem-drift");
        let drift_database = drift_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let drift_active = drift_root
            .join(SECRET_DIRECTORY_NAME)
            .join("auth-keyring.v1");
        let drift_reservation = drift_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (drift_actor, drift_stores) = actor_and_stores(&drift_root).await;
        advance_initialization_to_installed_active_key(&drift_actor).await;
        let gate = ActorTestGate::new();
        let run = drift_actor
            .start_commit_initialization_final_lifecycle_with_post_mutation_gate(gate.clone())
            .expect("post-mutation gated final command");
        gate.wait_until_reached();
        owner_file(&drift_active, b"POV");
        gate.resume();
        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(auth_lifecycle_state(&drift_database), "active");
        assert_eq!(fs::read(&drift_active).expect("drift retained"), b"POV");
        assert!(drift_reservation.exists());
        assert!(matches!(
            drift_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        drift_actor.shutdown().await.expect("drift actor shutdown");
    }

    #[tokio::test]
    async fn dropped_final_lifecycle_receiver_does_not_cancel_actor_work() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_installed_active_key(&actor).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_commit_initialization_final_lifecycle_with_gate(gate.clone())
            .expect("gated final lifecycle");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();
        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("final lifecycle waiter cancelled")
                .is_cancelled()
        );
        gate.resume();

        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected post-drop actor error: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached final lifecycle")
        .expect("post-final reconciliation");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingCleanupRename
            )
        );
        assert_eq!(auth_lifecycle_state(&database), "active");
        assert_eq!(
            actor
                .commit_initialization_final_lifecycle()
                .await
                .expect("replay after receiver drop"),
            AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop keeps store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_cleanup_is_exact_replayable_and_redacted() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let transition =
            secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let cleanup = secrets.join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_awaiting_cleanup(&actor).await;
        let active_inode = fs::symlink_metadata(&active)
            .expect("active inode before cleanup")
            .ino();

        let completed = actor
            .cleanup_initialization()
            .await
            .expect("completed initialization cleanup");
        assert_eq!(completed, AuthInitializationCleanupOutcome::Completed);
        assert!(!transition.exists());
        assert!(!cleanup.exists());
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode after cleanup")
                .ino(),
            active_inode
        );
        let mut names: Vec<String> = fs::read_dir(&secrets)
            .expect("terminal secret directory")
            .map(|entry| {
                entry
                    .expect("terminal secret entry")
                    .file_name()
                    .into_string()
                    .expect("canonical terminal name")
            })
            .collect();
        names.sort();
        assert_eq!(names, ["auth-keyring.v1", AUTH_LOCK_FILE_NAME]);
        assert_eq!(auth_lifecycle_state(&database), "active");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("terminal reconciliation"),
            AuthInitializationReconciliation::InitializationComplete
        );

        let replay = actor
            .cleanup_initialization()
            .await
            .expect("cleanup replay");
        assert_eq!(replay, AuthInitializationCleanupOutcome::AlreadyCompleted);
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode after cleanup replay")
                .ino(),
            active_inode
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        let rendered = format!("{completed:?} {replay:?}");
        for secret in [
            fixture.login_id,
            fixture.kid.as_str(),
            fixture.password_phc.as_str(),
            fixture.recovery_phc.as_str(),
        ] {
            assert!(!rendered.contains(secret), "{secret}");
        }
        stores
            .conversation
            .report()
            .await
            .expect("cleanup and replay keep store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_cleanup_accepts_historical_canonical_source() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (actor, stores) = actor_and_stores(&root).await;
        let historical = legacy_metadata(&fixture.metadata);
        write_prepared_reservation(&root, &fixture, &historical);
        commit_initializing_source_with_provenance(
            &database,
            &fixture,
            &legacy_policy_provenance(),
        );
        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("historical active key install"),
            AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
        assert_eq!(
            actor
                .commit_initialization_final_lifecycle()
                .await
                .expect("historical final lifecycle"),
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );

        assert_eq!(
            actor
                .cleanup_initialization()
                .await
                .expect("historical cleanup"),
            AuthInitializationCleanupOutcome::Completed
        );
        assert_eq!(auth_lifecycle_state(&database), "active");
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("historical terminal reconciliation"),
            AuthInitializationReconciliation::InitializationComplete
        );
        stores
            .conversation
            .report()
            .await
            .expect("historical cleanup keeps store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_cleanup_durability_faults_resume_from_exact_phase() {
        let directory = tempdir().expect("temporary parent");
        let cases = [
            (
                AuthInitializationCleanupTestFault::Rename,
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupStagedRemoval,
                ),
            ),
            (
                AuthInitializationCleanupTestFault::Staged,
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupPreparedRemoval,
                ),
            ),
            (
                AuthInitializationCleanupTestFault::Prepared,
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupMetadataRemoval,
                ),
            ),
            (
                AuthInitializationCleanupTestFault::Metadata,
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupDirectoryRemoval,
                ),
            ),
            (
                AuthInitializationCleanupTestFault::Directory,
                AuthInitializationReconciliation::InitializationComplete,
            ),
        ];

        for (index, (fault, expected_phase)) in cases.into_iter().enumerate() {
            let root = directory.path().join(format!("case-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_awaiting_cleanup(&actor).await;
            assert_eq!(
                actor
                    .start_cleanup_initialization_with_fault(fault)
                    .expect("faulted cleanup command")
                    .await
                    .unwrap_err(),
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            );
            assert_eq!(auth_lifecycle_state(&database), "active");
            assert_eq!(auth_audit_shape(&database), (1, Some(1)));
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
            actor.shutdown().await.expect("faulted actor shutdown");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("fault phase reconciliation"),
                expected_phase,
                "{fault:?}"
            );
            let resumed = fresh_actor
                .cleanup_initialization()
                .await
                .expect("resumed cleanup");
            assert_eq!(
                resumed,
                if expected_phase == AuthInitializationReconciliation::InitializationComplete {
                    AuthInitializationCleanupOutcome::AlreadyCompleted
                } else {
                    AuthInitializationCleanupOutcome::Completed
                },
                "{fault:?}"
            );
            assert_eq!(auth_lifecycle_state(&database), "active");
            assert_eq!(auth_audit_shape(&database), (1, Some(1)));
            fresh_stores
                .conversation
                .report()
                .await
                .expect("resumed cleanup keeps store healthy");
            fresh_actor.shutdown().await.expect("fresh actor shutdown");
        }
    }

    #[tokio::test]
    async fn cleanup_rename_race_never_overwrites_destination() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let transition =
            secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let cleanup = secrets.join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_awaiting_cleanup(&actor).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_cleanup_initialization_with_before_rename_gate(gate.clone())
            .expect("gated cleanup rename");
        gate.wait_until_reached();
        fs::create_dir(&cleanup).expect("raced cleanup destination");
        fs::set_permissions(&cleanup, fs::Permissions::from_mode(0o700))
            .expect("cleanup destination mode");
        gate.resume();

        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(transition.is_dir());
        assert!(cleanup.is_dir());
        assert_eq!(
            fs::read_dir(&cleanup)
                .expect("raced cleanup directory")
                .count(),
            0
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn cleanup_pre_rename_source_and_active_drift_preserve_transition() {
        let directory = tempdir().expect("temporary parent");

        let source_root = directory.path().join("source-drift");
        let source_database = source_root
            .join(STORE_DIRECTORY_NAME)
            .join("conversation.sqlite3");
        let source_secrets = source_root.join(SECRET_DIRECTORY_NAME);
        let source_transition =
            source_secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let source_cleanup =
            source_secrets.join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (source_actor, source_stores) = actor_and_stores(&source_root).await;
        advance_initialization_to_awaiting_cleanup(&source_actor).await;
        let source_gate = ActorTestGate::new();
        let source_run = source_actor
            .start_cleanup_initialization_with_before_rename_gate(source_gate.clone())
            .expect("source-drift cleanup command");
        source_gate.wait_until_reached();
        RawConnection::open(&source_database)
            .expect("cleanup source drift writer")
            .execute(
                "UPDATE auth_password_credentials
                 SET credential_revision = 2,
                     updated_at_micros = updated_at_micros + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("cleanup source drift");
        source_gate.resume();

        assert_eq!(
            source_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        assert!(source_transition.is_dir());
        assert!(!source_cleanup.exists());
        assert_eq!(auth_lifecycle_state(&source_database), "active");
        assert!(matches!(
            source_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        source_actor
            .shutdown()
            .await
            .expect("source-drift actor shutdown");

        let active_root = directory.path().join("active-drift");
        let active_secrets = active_root.join(SECRET_DIRECTORY_NAME);
        let active_key = active_secrets.join("auth-keyring.v1");
        let active_transition =
            active_secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let active_cleanup =
            active_secrets.join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (active_actor, active_stores) = actor_and_stores(&active_root).await;
        advance_initialization_to_awaiting_cleanup(&active_actor).await;
        let active_gate = ActorTestGate::new();
        let active_run = active_actor
            .start_cleanup_initialization_with_before_rename_gate(active_gate.clone())
            .expect("active-drift cleanup command");
        active_gate.wait_until_reached();
        owner_file(&active_key, b"POV-before-cleanup");
        active_gate.resume();

        assert_eq!(
            active_run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert!(active_transition.is_dir());
        assert!(!active_cleanup.exists());
        assert_eq!(
            fs::read(&active_key).expect("pre-rename active drift retained"),
            b"POV-before-cleanup"
        );
        assert!(matches!(
            active_stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        active_actor
            .shutdown()
            .await
            .expect("active-drift actor shutdown");
    }

    #[tokio::test]
    async fn cleanup_post_removal_active_drift_poison_preserves_observed_state() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let transition =
            secrets.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let cleanup = secrets.join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_awaiting_cleanup(&actor).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_cleanup_initialization_with_after_cleanup_gate(gate.clone())
            .expect("post-cleanup gate");
        gate.wait_until_reached();
        owner_file(&active, b"POV-after-cleanup");
        gate.resume();

        assert_eq!(
            run.await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged
            ))
        );
        assert_eq!(auth_lifecycle_state(&database), "active");
        assert!(!transition.exists());
        assert!(!cleanup.exists());
        assert_eq!(
            fs::read(&active).expect("drifted active retained"),
            b"POV-after-cleanup"
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn cleanup_rejects_pre_final_and_illegal_partial_states_without_mutation() {
        let directory = tempdir().expect("temporary parent");

        let pre_final_root = directory.path().join("pre-final");
        let pre_final_transition = pre_final_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (pre_final_actor, pre_final_stores) = actor_and_stores(&pre_final_root).await;
        advance_initialization_to_installed_active_key(&pre_final_actor).await;
        let pre_final = pre_final_actor
            .cleanup_initialization()
            .await
            .expect("typed pre-final cleanup");
        assert_eq!(
            pre_final,
            AuthInitializationCleanupOutcome::NotCleanable(
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingFinalDbCas
                )
            )
        );
        assert!(pre_final_transition.exists());
        pre_final_stores
            .conversation
            .report()
            .await
            .expect("pre-final rejection stays healthy");
        pre_final_actor
            .shutdown()
            .await
            .expect("pre-final actor shutdown");

        let partial_root = directory.path().join("illegal-subset");
        let partial_cleanup = partial_root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-cleanup-initialize-11111111-1111-4111-8111-111111111111");
        let (partial_actor, partial_stores) = actor_and_stores(&partial_root).await;
        advance_initialization_to_awaiting_cleanup(&partial_actor).await;
        assert!(
            partial_actor
                .start_cleanup_initialization_with_fault(
                    AuthInitializationCleanupTestFault::Rename,
                )
                .expect("rename fault")
                .await
                .is_err()
        );
        partial_actor
            .shutdown()
            .await
            .expect("partial actor shutdown");
        drop(partial_stores);
        fs::remove_file(partial_cleanup.join("prepared"))
            .expect("create illegal metadata+staged subset");

        let (fresh_actor, fresh_stores) = actor_and_stores(&partial_root).await;
        let blocker = AuthInitializationReconciliation::Blocked(
            AuthInitializationBlocker::InconsistentDbFilesystem,
        );
        assert_eq!(
            fresh_actor
                .inspect_initialization_reconciliation()
                .await
                .expect("illegal subset reconciliation"),
            blocker
        );
        assert_eq!(
            fresh_actor
                .cleanup_initialization()
                .await
                .expect("typed illegal-subset cleanup"),
            AuthInitializationCleanupOutcome::NotCleanable(blocker)
        );
        assert!(partial_cleanup.join("metadata").exists());
        assert!(partial_cleanup.join("staged-keyring").exists());
        fresh_stores
            .conversation
            .report()
            .await
            .expect("illegal subset rejection stays healthy");
        fresh_actor.shutdown().await.expect("fresh actor shutdown");
    }

    #[tokio::test]
    async fn terminal_cleanup_envelope_rejects_lifecycle_key_mismatch() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_awaiting_cleanup(&actor).await;
        assert_eq!(
            actor
                .cleanup_initialization()
                .await
                .expect("initial cleanup"),
            AuthInitializationCleanupOutcome::Completed
        );
        actor.shutdown().await.expect("initial actor shutdown");
        drop(stores);
        let alternate = Keyring::from_test_seeds(1, SOURCE_AT_MICROS as u64 - 1, [0x32; 32], None)
            .expect("alternate terminal keyring")
            .encode();
        owner_file(&active, alternate.expose_secret());

        let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
        let blocker = AuthInitializationReconciliation::Blocked(
            AuthInitializationBlocker::UnsupportedLifecycleState,
        );
        assert_eq!(
            fresh_actor
                .inspect_initialization_reconciliation()
                .await
                .expect("terminal mismatch reconciliation"),
            blocker
        );
        assert_eq!(
            fresh_actor
                .cleanup_initialization()
                .await
                .expect("typed terminal mismatch"),
            AuthInitializationCleanupOutcome::NotCleanable(blocker)
        );
        fresh_stores
            .conversation
            .report()
            .await
            .expect("terminal mismatch is typed and non-poisoning");
        fresh_actor.shutdown().await.expect("fresh actor shutdown");
    }

    #[tokio::test]
    async fn dropped_cleanup_receiver_does_not_cancel_actor_work() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_awaiting_cleanup(&actor).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_cleanup_initialization_with_gate(gate.clone())
            .expect("gated cleanup");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();
        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("cleanup waiter cancelled")
                .is_cancelled()
        );
        gate.resume();

        let readback = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match actor.start_initialization_reconciliation() {
                    Ok(run) => break run.await,
                    Err(AuthMaintenanceActorError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected post-drop actor error: {error:?}"),
                }
            }
        })
        .await
        .expect("actor completes detached cleanup")
        .expect("post-cleanup reconciliation");
        assert_eq!(
            readback,
            AuthInitializationReconciliation::InitializationComplete
        );
        assert_eq!(
            actor
                .cleanup_initialization()
                .await
                .expect("cleanup replay after receiver drop"),
            AuthInitializationCleanupOutcome::AlreadyCompleted
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop keeps store healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn clean_inspection_is_read_only_and_any_non_lock_artifact_is_occupied() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secret_root = root.join(SECRET_DIRECTORY_NAME);
        let (actor, stores) = actor_and_stores(&root).await;

        let clean = actor
            .inspect_clean_instance()
            .await
            .expect("pristine inspection");
        assert_eq!(clean, AuthCleanInstanceState::Clean);
        assert!(!format!("{clean:?}").contains(root.to_string_lossy().as_ref()));

        for (name, is_directory, owner_only) in [
            ("auth-keyring.v1", false, true),
            (
                ".auth-transition-initialize-00000000-0000-4000-8000-000000000001",
                true,
                true,
            ),
            (
                ".auth-cleanup-planned-00000000-0000-4000-8000-000000000002",
                true,
                true,
            ),
            (
                ".auth-keyring-install-00000000-0000-4000-8000-000000000003.tmp",
                false,
                true,
            ),
            (".DS_Store", false, false),
        ] {
            let artifact = secret_root.join(name);
            if is_directory {
                fs::create_dir(&artifact).expect("synthetic artifact directory");
            } else {
                fs::write(&artifact, b"synthetic").expect("synthetic artifact file");
            }
            if owner_only {
                fs::set_permissions(
                    &artifact,
                    fs::Permissions::from_mode(if is_directory { 0o700 } else { 0o600 }),
                )
                .expect("owner-only artifact");
            }
            assert_eq!(
                actor
                    .inspect_clean_instance()
                    .await
                    .expect("occupied inspection"),
                AuthCleanInstanceState::Occupied
            );
            if is_directory {
                assert!(artifact.is_dir());
                fs::remove_dir(artifact).expect("remove synthetic artifact directory");
            } else {
                assert_eq!(
                    fs::read(&artifact).expect("artifact retained"),
                    b"synthetic"
                );
                fs::remove_file(artifact).expect("remove synthetic artifact file");
            }
        }

        let external = directory.path().join("external-canary");
        fs::write(&external, b"external").expect("external canary");
        let artifact_link = secret_root.join("artifact-link");
        symlink(&external, &artifact_link).expect("artifact symlink");
        assert_eq!(
            actor
                .inspect_clean_instance()
                .await
                .expect("symlink is occupied without being followed"),
            AuthCleanInstanceState::Occupied
        );
        assert_eq!(fs::read(&external).expect("external retained"), b"external");
        fs::remove_file(artifact_link).expect("remove artifact link");

        let invalid_name = OsString::from_vec(b"artifact-\xff".to_vec());
        let invalid_artifact = secret_root.join(invalid_name);
        match fs::write(&invalid_artifact, b"invalid-name") {
            Ok(()) => {
                assert_eq!(
                    actor
                        .inspect_clean_instance()
                        .await
                        .expect("non-UTF-8 artifact is occupied"),
                    AuthCleanInstanceState::Occupied
                );
                assert_eq!(
                    fs::read(&invalid_artifact).expect("non-UTF-8 artifact retained"),
                    b"invalid-name"
                );
                fs::remove_file(invalid_artifact).expect("remove non-UTF-8 artifact");
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
                ) => {}
            Err(error) => panic!("unexpected non-UTF-8 artifact error: {error}"),
        }

        assert_eq!(
            actor
                .inspect_clean_instance()
                .await
                .expect("clean after synthetic artifacts"),
            AuthCleanInstanceState::Clean
        );
        stores
            .conversation
            .report()
            .await
            .expect("occupied observations do not poison the store");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_reconciliation_distinguishes_clean_and_early_pre_source_phases() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secret_root = root.join(SECRET_DIRECTORY_NAME);
        let reservation =
            secret_root.join(".auth-transition-initialize-11111111-1111-4111-8111-111111111111");
        let (actor, stores) = actor_and_stores(&root).await;

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("clean reconciliation"),
            AuthInitializationReconciliation::CleanUninitialized
        );

        fs::create_dir(&reservation).expect("empty initialization reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))
            .expect("owner-only reservation");
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("empty reservation reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::ReservationOnly,
                recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
            }
        );

        owner_file(&reservation.join("metadata"), b"POV");
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("partial metadata reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::MetadataIncomplete,
                recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
            }
        );

        let fixture = initialization_fixture("owner_01");
        owner_file(
            &reservation.join("metadata"),
            fixture.metadata.expose_secret(),
        );
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("complete metadata reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::MetadataComplete,
                recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
            }
        );

        owner_file(
            &reservation.join("staged-keyring"),
            &fixture.staged.expose_secret()[..32],
        );
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("partial staged reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::StagedIncomplete,
                recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
            }
        );

        owner_file(
            &reservation.join("staged-keyring"),
            fixture.staged.expose_secret(),
        );
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("complete staged reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::StagedComplete,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            }
        );

        owner_file(&reservation.join("prepared"), b"");
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("prepared reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            }
        );

        let historical = legacy_metadata(&fixture.metadata);
        owner_file(&reservation.join("metadata"), historical.expose_secret());
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("historical prepared reconciliation"),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
            }
        );

        stores
            .conversation
            .report()
            .await
            .expect("pre-source observations do not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_reconciliation_blocks_unknown_artifacts_without_poison_or_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let artifact = root.join(SECRET_DIRECTORY_NAME).join("unknown-artifact");
        let (actor, stores) = actor_and_stores(&root).await;
        fs::write(&artifact, b"preserve-me").expect("unknown artifact");

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("blocked reconciliation"),
            AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::UnrecognizedArtifacts
            )
        );
        assert_eq!(
            fs::read(&artifact).expect("unknown artifact retained"),
            b"preserve-me"
        );
        stores
            .conversation
            .report()
            .await
            .expect("blocked observation does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_reconciliation_reports_every_forward_only_install_phase() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let install =
            secrets.join(".auth-keyring-install-11111111-1111-4111-8111-111111111111.tmp");
        let active = secrets.join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        let fixture = initialization_fixture("owner_01");
        write_prepared_reservation(&root, &fixture, &fixture.metadata);
        commit_initializing_source(&database, &fixture);
        RawConnection::open(&database)
            .expect("unrelated sequence writer")
            .execute(
                "INSERT INTO sqlite_sequence(name, seq)
                 VALUES ('synthetic_unrelated_sequence', 99)",
                [],
            )
            .expect("unrelated sqlite sequence");

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("awaiting install observation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp
            )
        );

        owner_file(&install, b"");
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("empty prefix observation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::InstallTempPrefix
            )
        );
        owner_file(
            &install,
            &fixture.staged.expose_secret()[..fixture.staged.expose_secret().len() - 1],
        );
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("length minus one prefix observation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::InstallTempPrefix
            )
        );
        owner_file(&install, fixture.staged.expose_secret());
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("exact install observation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::InstallTempExact
            )
        );

        fs::remove_file(&install).expect("remove install temp");
        owner_file(&active, fixture.staged.expose_secret());
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("installed active observation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingFinalDbCas
            )
        );

        owner_file(&install, fixture.staged.expose_secret());
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("active plus temp is blocked"),
            AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem
            )
        );
        assert_eq!(
            fs::read(&install).expect("blocked install retained"),
            fixture.staged.expose_secret()
        );
        assert_eq!(
            fs::read(&active).expect("blocked active retained"),
            fixture.staged.expose_secret()
        );
        stores
            .conversation
            .report()
            .await
            .expect("forward and blocked observations do not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_source_metadata_mismatch_is_blocked_without_poisoning() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let database_fixture = initialization_fixture("owner_01");
        let reservation_fixture = initialization_fixture("owner_02");
        let reservation =
            write_prepared_reservation(&root, &reservation_fixture, &reservation_fixture.metadata);
        commit_initializing_source(&database, &database_fixture);

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("source mismatch observation"),
            AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem
            )
        );
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("metadata retained"),
            reservation_fixture.metadata.expose_secret()
        );
        stores
            .conversation
            .report()
            .await
            .expect("canonical source mismatch is not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn sentinel_and_legacy_policy_mismatches_are_blocked_in_both_directions() {
        let directory = tempdir().expect("temporary parent");

        for (index, metadata_is_sentinel) in [true, false].into_iter().enumerate() {
            let root = directory.path().join(format!("policy-mismatch-{index}"));
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let fixture = initialization_fixture("owner_01");
            let legacy_metadata = legacy_metadata(&fixture.metadata);
            let reservation_metadata = if metadata_is_sentinel {
                &fixture.metadata
            } else {
                &legacy_metadata
            };
            let database_provenance = if metadata_is_sentinel {
                legacy_policy_provenance()
            } else {
                NO_BLOCKLIST_CHECK_SENTINEL.to_owned()
            };
            let (actor, stores) = actor_and_stores(&root).await;
            let reservation = write_prepared_reservation(&root, &fixture, reservation_metadata);
            commit_initializing_source_with_provenance(&database, &fixture, &database_provenance);

            assert_eq!(
                actor
                    .inspect_initialization_reconciliation()
                    .await
                    .expect("stable policy mismatch"),
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::InconsistentDbFilesystem
                )
            );
            assert_eq!(
                fs::read(reservation.join("metadata")).expect("mismatch evidence retained"),
                reservation_metadata.expose_secret()
            );
            assert_eq!(
                persisted_legacy_policy_provenance(&database),
                database_provenance
            );
            stores
                .conversation
                .report()
                .await
                .expect("stable mismatch is typed without poisoning");
            actor.shutdown().await.expect("joined mismatch actor");
        }
    }

    #[tokio::test]
    async fn initialization_source_reused_verifier_salt_is_structural_poison_without_metadata() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let mut fixture = initialization_fixture("owner_01");
        fixture.recovery_phc = Zeroizing::new(fixture.password_phc.as_str().to_owned());
        commit_initializing_source(&database, &fixture);

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn initialization_source_missing_seed_rows_is_structural_poison() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let fixture = initialization_fixture("owner_01");
        RawConnection::open(&database)
            .expect("lifecycle-only source writer")
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = ?3
                 WHERE singleton = 1 AND state = 'uninitialized'",
                params![fixture.kid, TEST_TRANSITION, SOURCE_AT_MICROS],
            )
            .expect("lifecycle-only initializing source");

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn initialization_source_auth_audit_sequence_drift_is_structural_poison() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let fixture = initialization_fixture("owner_01");
        commit_initializing_source(&database, &fixture);
        RawConnection::open(&database)
            .expect("audit sequence writer")
            .execute(
                "UPDATE sqlite_sequence SET seq = 2 WHERE name = 'auth_audit'",
                [],
            )
            .expect("drift audit sequence");

        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn legacy_policy_provenance_is_forward_only_after_exact_source_commit() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let fixture = initialization_fixture("owner_01");
        let historical = legacy_metadata(&fixture.metadata);
        write_prepared_reservation(&root, &fixture, &historical);
        let historical_version = legacy_policy_provenance();
        commit_initializing_source_with_provenance(&database, &fixture, &historical_version);

        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        assert_eq!(
            actor
                .inspect_initialization_reconciliation()
                .await
                .expect("historical exact source observation"),
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp
            )
        );
        assert_eq!(
            actor
                .commit_initialization_source()
                .await
                .expect("historical post-source replay"),
            AuthInitializationSourceOutcome::AlreadyCommitted
        );
        assert_eq!(auth_audit_shape(&database), (1, Some(1)));
        stores
            .conversation
            .report()
            .await
            .expect("historical exact source remains healthy");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn initialization_reconciliation_detects_database_drift_after_filesystem_b() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let fixture = initialization_fixture("owner_01");
        let (context, stores) = owned_context_and_stores(&root).await;
        write_prepared_reservation(&root, &fixture, &fixture.metadata);
        commit_initializing_source(&database, &fixture);

        let drift_database = database.clone();
        assert_eq!(
            context
                .inspect_initialization_reconciliation_with_checkpoints(
                    move || {
                        RawConnection::open(drift_database)
                            .expect("lifecycle drift writer")
                            .execute(
                                "UPDATE auth_key_lifecycle
                                 SET state = 'active',
                                     state_revision = 2,
                                     transition_kind = NULL,
                                     transition_id = NULL,
                                     updated_at_micros = ?1
                                 WHERE singleton = 1",
                                [SOURCE_AT_MICROS],
                            )
                            .expect("lifecycle drift");
                    },
                    || {},
                )
                .unwrap_err(),
            AuthStoreBindingError::ConversationStoreChanged
        );
        stores
            .conversation
            .report()
            .await
            .expect("direct test hook does not own actor poisoning");
    }

    #[tokio::test]
    async fn initialization_reconciliation_detects_mismatch_to_mismatch_source_drift() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let database_fixture = initialization_fixture("owner_01");
        let reservation_fixture = initialization_fixture("owner_02");
        let (context, stores) = owned_context_and_stores(&root).await;
        write_prepared_reservation(&root, &reservation_fixture, &reservation_fixture.metadata);
        commit_initializing_source(&database, &database_fixture);

        let drift_database = database.clone();
        let historical_version = legacy_policy_provenance();
        assert_eq!(
            context
                .inspect_initialization_reconciliation_with_checkpoints(
                    move || {
                        let writer =
                            RawConnection::open(drift_database).expect("source drift writer");
                        writer
                            .execute_batch(
                                "PRAGMA foreign_keys = OFF;
                                 PRAGMA recursive_triggers = OFF;",
                            )
                            .expect("test-only external tamper policy");
                        writer
                            .execute(
                                "INSERT OR REPLACE INTO auth_password_credentials(
                                    singleton,
                                    owner_id,
                                    verifier_phc,
                                    authenticator_state,
                                    credential_revision,
                                    blocklist_version,
                                    created_at_micros,
                                    updated_at_micros
                                 )
                                 SELECT
                                    singleton,
                                    owner_id,
                                    verifier_phc,
                                    authenticator_state,
                                    credential_revision,
                                    ?1,
                                    created_at_micros,
                                    updated_at_micros
                                 FROM auth_password_credentials
                                 WHERE singleton = 1",
                                [historical_version],
                            )
                            .expect("canonical mismatch-to-mismatch source drift");
                    },
                    || {},
                )
                .unwrap_err(),
            AuthStoreBindingError::ConversationStoreChanged
        );
        stores
            .conversation
            .report()
            .await
            .expect("direct test hook does not own actor poisoning");
    }

    #[tokio::test]
    async fn initialization_reconciliation_detects_filesystem_drift_after_database_b() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let fixture = initialization_fixture("owner_01");
        let (context, stores) = owned_context_and_stores(&root).await;
        let reservation = write_prepared_reservation(&root, &fixture, &fixture.metadata);
        let metadata_path = reservation.join("metadata");

        assert_eq!(
            context
                .inspect_initialization_reconciliation_with_checkpoints(
                    || {},
                    move || owner_file(&metadata_path, b"POV"),
                )
                .unwrap_err(),
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged)
        );
        assert_eq!(
            fs::read(reservation.join("metadata")).expect("drift artifact retained"),
            b"POV"
        );
        stores
            .conversation
            .report()
            .await
            .expect("direct test hook does not own actor poisoning");
    }

    #[tokio::test]
    async fn unsafe_known_artifact_is_preserved_and_poisons_before_unlock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let artifact = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        fs::write(&artifact, [0_u8; 262]).expect("oversized known artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))
            .expect("owner-only artifact");

        let error = actor.inspect_clean_instance().await.unwrap_err();
        assert_eq!(
            error,
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact
            ))
        );
        assert_eq!(
            fs::metadata(&artifact)
                .expect("unsafe artifact retained")
                .len(),
            262
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn extended_acl_artifact_is_preserved_and_poisons_before_unlock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let artifact = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        fs::write(&artifact, b"partial-keyring").expect("synthetic keyring artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))
            .expect("owner-only artifact");
        add_extended_acl(&artifact);

        let error = actor.inspect_clean_instance().await.unwrap_err();
        assert_eq!(
            error,
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact
            ))
        );
        assert_eq!(
            fs::read(&artifact).expect("ACL artifact retained"),
            b"partial-keyring"
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn dropped_clean_inspection_receiver_does_not_cancel_or_release_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_clean_instance_inspection_with_gate(gate.clone())
            .expect("gated clean inspection");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();

        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("inspection waiter is cancelled")
                .is_cancelled()
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        gate.resume();
        assert_eq!(
            actor
                .inspect_clean_instance()
                .await
                .expect("actor remains healthy"),
            AuthCleanInstanceState::Clean
        );
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop is not infrastructure poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn valid_non_uninitialized_lifecycle_is_occupied_without_poisoning() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let fixture = initialization_fixture("owner_01");
        commit_initializing_source(&database, &fixture);
        assert_eq!(
            actor
                .inspect_clean_instance()
                .await
                .expect("initializing inspection"),
            AuthCleanInstanceState::Occupied
        );

        let writer = RawConnection::open(&database).expect("synthetic lifecycle writer");
        writer
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'active',
                     state_revision = 2,
                     transition_kind = NULL,
                     transition_id = NULL,
                     updated_at_micros = ?1
                 WHERE singleton = 1",
                [SOURCE_AT_MICROS + 1],
            )
            .expect("active lifecycle");
        assert_eq!(
            actor
                .inspect_clean_instance()
                .await
                .expect("active inspection"),
            AuthCleanInstanceState::Occupied
        );

        writer
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'transitioning',
                     state_revision = 3,
                     expected_kid = ?1,
                     transition_kind = 'planned',
                     transition_id = ?2,
                     keyring_version = 2,
                     updated_at_micros = ?3
                 WHERE singleton = 1",
                params![OTHER_KID, OTHER_TRANSITION, SOURCE_AT_MICROS + 2],
            )
            .expect("transitioning lifecycle");
        assert_eq!(
            actor
                .inspect_clean_instance()
                .await
                .expect("transitioning inspection"),
            AuthCleanInstanceState::Occupied
        );
        drop(writer);

        stores
            .conversation
            .report()
            .await
            .expect("existing lifecycle observation does not poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn inconsistent_uninitialized_auth_rows_poison_before_unlock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let (actor, stores) = actor_and_stores(&root).await;
        let writer = RawConnection::open(&database).expect("synthetic auth writer");
        writer
            .execute(
                "INSERT INTO auth_accounts(
                    singleton,
                    owner_id,
                    login_id,
                    account_state,
                    credential_version,
                    account_revision,
                    created_at_micros,
                    updated_at_micros
                 ) VALUES (1, ?1, 'synthetic-owner', 'enabled', 1, 1, 1, 1)",
                params![[0x33_u8; 16]],
            )
            .expect("inconsistent auth account");
        drop(writer);

        let error = actor.inspect_clean_instance().await.unwrap_err();
        assert_eq!(
            error,
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));
        assert!(!rendered.contains("synthetic-owner"));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn oversized_secret_inventory_is_bounded_and_poisons() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secret_root = root.join(SECRET_DIRECTORY_NAME);
        let (actor, stores) = actor_and_stores(&root).await;
        for index in 0..33 {
            fs::write(
                secret_root.join(format!("synthetic-artifact-{index:02}")),
                b"x",
            )
            .expect("bounded synthetic artifact");
        }

        let error = actor.inspect_clean_instance().await.unwrap_err();
        assert_eq!(
            error,
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactInventoryLimit
            ))
        );
        assert!(!format!("{error:?} {error}").contains("synthetic-artifact"));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn dropped_result_receiver_does_not_cancel_or_release_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_revalidation_with_gate(gate.clone())
            .expect("gated revalidation");
        let waiter = tokio::spawn(run);
        gate.wait_until_reached();

        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("caller task is cancelled")
                .is_cancelled()
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        gate.resume();
        actor
            .revalidate()
            .await
            .expect("actor remains healthy after response receiver drop");
        stores
            .conversation
            .report()
            .await
            .expect("receiver drop is not infrastructure poison");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[tokio::test]
    async fn bounded_mailbox_rejects_excess_work_without_poisoning() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        let gate = ActorTestGate::new();
        let active = actor
            .start_revalidation_with_gate(gate.clone())
            .expect("active request");
        gate.wait_until_reached();
        let queued = actor.start_revalidation().expect("one queued request");
        assert_eq!(
            actor.start_revalidation().unwrap_err(),
            AuthMaintenanceActorError::Busy
        );

        gate.resume();
        active.await.expect("active request finishes");
        queued.await.expect("queued request finishes");
        stores
            .conversation
            .report()
            .await
            .expect("mailbox pressure does not poison store");
        actor.shutdown().await.expect("joined shutdown");
    }

    #[test]
    fn runtime_shutdown_cannot_release_lock_while_actor_command_is_running() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let (actor, stores) = runtime.block_on(actor_and_stores(&root));
        let gate = ActorTestGate::new();
        let run = actor
            .start_revalidation_with_gate(gate.clone())
            .expect("gated revalidation");
        runtime.spawn(run);
        gate.wait_until_reached();

        drop(actor);
        drop(runtime);
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        gate.resume();
        wait_until_lock_available(&root);
        drop(stores);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_shutdown_waiter_cannot_cancel_join_or_release_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_revalidation_with_gate(gate.clone())
            .expect("gated revalidation");
        gate.wait_until_reached();
        let shutdown = actor.start_shutdown().expect("detached joined shutdown");
        assert!(
            !format!("{shutdown:?}").contains(root.to_string_lossy().as_ref()),
            "shutdown Debug must not disclose the instance path"
        );
        let waiter = tokio::spawn(shutdown);

        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("shutdown waiter is cancelled")
                .is_cancelled()
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        gate.resume();
        run.await.expect("accepted command completes");
        wait_until_lock_available(&root);
        stores
            .conversation
            .report()
            .await
            .expect("cancelled shutdown waiter does not poison store");
    }

    #[tokio::test]
    async fn command_panic_poisons_store_before_actor_releases_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, stores) = actor_and_stores(&root).await;

        assert_eq!(
            actor
                .start_panic()
                .expect("panic command accepted")
                .await
                .unwrap_err(),
            AuthMaintenanceActorError::OperationFailed
        );
        assert_eq!(
            actor.revalidate().await.unwrap_err(),
            AuthMaintenanceActorError::Poisoned
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        actor.shutdown().await.expect("poisoned actor can join");
        AuthInstanceLayout::open_or_create(&root)
            .expect("layout after poisoned shutdown")
            .lock()
            .expect("poisoned actor releases lock only after join");
    }

    #[tokio::test]
    async fn admitted_identity_drift_poisons_store_and_keeps_lock_until_shutdown() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let store_root = root.join(STORE_DIRECTORY_NAME);
        let (actor, stores) = actor_and_stores(&root).await;
        let database_path = store_root.join(stores.conversation.file_name());
        let moved_database_path = store_root.join("moved-conversation.sqlite3");

        fs::rename(&database_path, &moved_database_path).expect("move bound database");
        fs::copy(&moved_database_path, &database_path).expect("replacement database inode");
        fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");

        assert_eq!(
            actor.revalidate().await.unwrap_err(),
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::ConversationStoreUnavailable)
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );

        actor.shutdown().await.expect("joined poisoned shutdown");
    }

    #[tokio::test]
    async fn held_lock_path_replacement_is_never_treated_as_the_clean_artifact() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let secret_root = root.join(SECRET_DIRECTORY_NAME);
        let lock_path = secret_root.join(AUTH_LOCK_FILE_NAME);
        let moved_lock_path = secret_root.join("moved-maintenance-lock");
        let (actor, stores) = actor_and_stores(&root).await;

        fs::rename(&lock_path, &moved_lock_path).expect("move held lock path");
        fs::write(&lock_path, b"").expect("replacement lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("replacement lock mode");

        let error = actor.inspect_clean_instance().await.unwrap_err();
        assert_eq!(
            error,
            AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                SecretFsError::IdentityChanged
            ))
        );
        assert!(!format!("{error:?} {error}").contains(root.to_string_lossy().as_ref()));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined poisoned shutdown");
        assert!(moved_lock_path.exists());
        assert!(lock_path.exists());
    }

    #[tokio::test]
    async fn planned_rotation_prepares_replays_and_rolls_back_to_exact_clean_active_state() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("active bytes before planned rotation");
        let active_inode_before = fs::symlink_metadata(&active)
            .expect("active metadata before planned rotation")
            .ino();

        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("clean active reconciliation"),
            AuthPlannedRotationReconciliation::CleanActive
        );
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("prepared planned rotation"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("replayed planned preparation"),
            AuthPlannedRotationPrepareOutcome::AlreadyPrepared
        );
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("prepared planned reconciliation"),
            AuthPlannedRotationReconciliation::PlannedPreSource {
                phase: AuthPlannedRotationPreSourcePhase::Prepared,
                recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
            }
        );
        assert_eq!(
            actor
                .rollback_planned_rotation_pre_source()
                .await
                .expect("planned rollback"),
            AuthPlannedRotationRollbackOutcome::RolledBack
        );
        assert_eq!(
            actor
                .rollback_planned_rotation_pre_source()
                .await
                .expect("clean planned rollback replay"),
            AuthPlannedRotationRollbackOutcome::AlreadyClean
        );
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("terminal planned reconciliation"),
            AuthPlannedRotationReconciliation::CleanActive
        );
        assert_eq!(planned_source_snapshot(&database), source_before);
        assert_eq!(
            fs::read(&active).expect("active bytes after planned rollback"),
            active_before
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active metadata after planned rollback")
                .ino(),
            active_inode_before
        );
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined planned actor");
    }

    #[tokio::test]
    async fn retire_prepares_replays_and_rolls_back_to_exact_verify_only_state() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("verify-only active bytes");
        let active_inode_before = fs::symlink_metadata(&active)
            .expect("verify-only active metadata")
            .ino();
        assert_eq!(active_before.len(), 261);

        assert_eq!(
            actor
                .inspect_retire_reconciliation()
                .await
                .expect("retire-ready reconciliation"),
            AuthRetireReconciliation::ReadyToRetire
        );
        assert_eq!(
            actor
                .prepare_retire(retire_preparation(&root))
                .await
                .expect("prepared retire"),
            AuthRetirePrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .prepare_retire(retire_preparation(&root))
                .await
                .expect("replayed retire preparation"),
            AuthRetirePrepareOutcome::AlreadyPrepared
        );
        assert_eq!(
            actor
                .inspect_retire_reconciliation()
                .await
                .expect("prepared retire reconciliation"),
            AuthRetireReconciliation::RetirePreSource {
                phase: AuthRetirePreSourcePhase::Prepared,
                recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
            }
        );
        assert_eq!(
            actor
                .rollback_retire_pre_source()
                .await
                .expect("retire rollback"),
            AuthRetireRollbackOutcome::RolledBack
        );
        assert_eq!(
            actor
                .rollback_retire_pre_source()
                .await
                .expect("retire rollback replay"),
            AuthRetireRollbackOutcome::AlreadyReady
        );
        assert_eq!(
            actor
                .inspect_retire_reconciliation()
                .await
                .expect("terminal retire reconciliation"),
            AuthRetireReconciliation::ReadyToRetire
        );
        assert_eq!(planned_source_snapshot(&database), source_before);
        assert_eq!(
            fs::read(&active).expect("active bytes preserved"),
            active_before
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active inode preserved")
                .ino(),
            active_inode_before
        );
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined retire actor");
    }

    #[tokio::test]
    async fn retire_source_exchange_final_cas_and_cleanup_complete_exactly_and_replay() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        let before = current_active_keyring(&root);
        let before_kid = before.active_kid();
        let before_activation = before.active_activated_at();
        assert_eq!(before.version().get(), 2);
        assert!(before.verify_only_facts().is_some());

        assert_eq!(
            actor
                .prepare_retire(retire_preparation(&root))
                .await
                .expect("prepare retire"),
            AuthRetirePrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_retire_source()
                .await
                .expect("commit retire source"),
            AuthRetireSourceOutcome::Committed
        );
        assert_eq!(
            actor
                .commit_retire_source()
                .await
                .expect("replay retire source"),
            AuthRetireSourceOutcome::AlreadyCommitted
        );
        assert_eq!(
            actor
                .inspect_retire_reconciliation()
                .await
                .expect("retire awaiting install"),
            AuthRetireReconciliation::RetireForwardOnly(
                AuthRetireForwardPhase::AwaitingInstallTemp
            )
        );
        assert_eq!(
            actor
                .install_retire_active_key()
                .await
                .expect("install retired active key"),
            AuthRetireActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
        assert_eq!(
            actor
                .install_retire_active_key()
                .await
                .expect("replay retired active key"),
            AuthRetireActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
        );
        assert_eq!(
            actor
                .commit_retire_final_lifecycle()
                .await
                .expect("commit retire final lifecycle"),
            AuthRetireFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        assert_eq!(
            actor
                .commit_retire_final_lifecycle()
                .await
                .expect("replay retire final lifecycle"),
            AuthRetireFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup
        );
        assert_eq!(
            actor.cleanup_retire().await.expect("cleanup retire"),
            AuthRetireCleanupOutcome::Completed
        );
        assert_eq!(
            actor.cleanup_retire().await.expect("replay retire cleanup"),
            AuthRetireCleanupOutcome::AlreadyCompleted
        );
        assert_eq!(
            actor
                .inspect_retire_reconciliation()
                .await
                .expect("terminal retire"),
            AuthRetireReconciliation::CleanActiveOnly
        );

        let retired = current_active_keyring(&root);
        assert_eq!(fs::read(&active).expect("retired keyring").len(), 170);
        assert_eq!(retired.version().get(), 3);
        assert_eq!(retired.active_kid(), before_kid);
        assert_eq!(retired.active_activated_at(), before_activation);
        assert!(retired.verify_only_facts().is_none());
        let snapshot = planned_source_snapshot(&database);
        assert_eq!(
            snapshot.lifecycle,
            (
                "active".to_owned(),
                6,
                Some(before_kid.as_str().to_owned()),
                None,
                None,
                Some(3),
                RETIRE_AT_MICROS as i64,
            )
        );
        assert_eq!(snapshot.audit_count, 3);
        let retire_action: String = RawConnection::open(&database)
            .expect("retire audit reader")
            .query_row(
                "SELECT action FROM auth_audit WHERE audit_id = ?1",
                [RETIRE_AUDIT.as_slice()],
                |row| row.get(0),
            )
            .expect("retire audit");
        assert_eq!(retire_action, "key_retired");
        assert!(stores.conversation.report().await.is_ok());
        actor
            .shutdown()
            .await
            .expect("joined completed retire actor");
    }

    #[tokio::test]
    async fn retire_source_durability_faults_preserve_pre_source_evidence() {
        for fault in [
            AuthPlannedRotationSourceDurabilityTestFault::Metadata,
            AuthPlannedRotationSourceDurabilityTestFault::Staged,
            AuthPlannedRotationSourceDurabilityTestFault::Prepared,
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("verify-only active bytes");
            assert_eq!(
                actor
                    .prepare_retire(retire_preparation(&root))
                    .await
                    .expect("prepared retire source fixture"),
                AuthRetirePrepareOutcome::Prepared
            );

            let failure = actor
                .start_commit_retire_source_with_durability_fault(fault)
                .expect("admitted retire source")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            actor
                .shutdown()
                .await
                .expect("joined poisoned retire actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh prepared retire reconciliation"),
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::Prepared,
                    recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
                }
            );
            assert_eq!(
                fresh_actor
                    .commit_retire_source()
                    .await
                    .expect("fresh retire source commit"),
                AuthRetireSourceOutcome::Committed
            );
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh retire forward reconciliation"),
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingInstallTemp
                )
            );
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh retire source actor");
        }
    }

    #[tokio::test]
    async fn retire_source_commit_uncertainty_is_classified_from_fresh_state() {
        for (fault, expected_outcome, expected_reconciliation) in [
            (
                AuthPlannedRotationSourceMutationTestFault::AfterCommitResponseLoss,
                AuthRetireSourceOutcome::Committed,
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingInstallTemp,
                ),
            ),
            (
                AuthPlannedRotationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                AuthRetireSourceOutcome::ConfirmedNotCommitted,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::Prepared,
                    recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
                },
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("verify-only active bytes");
            assert_eq!(
                actor
                    .prepare_retire(retire_preparation(&root))
                    .await
                    .expect("prepared retire source fixture"),
                AuthRetirePrepareOutcome::Prepared
            );

            assert_eq!(
                actor
                    .start_commit_retire_source_with_fault(fault)
                    .expect("admitted retire source")
                    .await
                    .expect("classified retire source result"),
                expected_outcome
            );
            assert_eq!(
                actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("retire source reconciliation"),
                expected_reconciliation
            );
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            let source_after = planned_source_snapshot(&database);
            if expected_outcome == AuthRetireSourceOutcome::Committed {
                assert_eq!(source_after.lifecycle.0, "transitioning");
                assert_eq!(source_after.audit_count, source_before.audit_count + 1);
            } else {
                assert_eq!(source_after, source_before);
            }
            assert!(stores.conversation.report().await.is_ok());
            actor.shutdown().await.expect("joined retire source actor");
        }
    }

    #[tokio::test]
    async fn retire_active_key_install_faults_resume_from_exact_durable_phase() {
        for (fault, expected) in [
            (
                AuthPlannedRotationActiveKeyInstallTestFault::InstallTempDurable,
                AuthRetireForwardPhase::InstallTempExact,
            ),
            (
                AuthPlannedRotationActiveKeyInstallTestFault::ExchangeDurable,
                AuthRetireForwardPhase::AwaitingOldActiveTempRemoval,
            ),
            (
                AuthPlannedRotationActiveKeyInstallTestFault::OldActiveTempRemoved,
                AuthRetireForwardPhase::AwaitingFinalDbCas,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let secrets = root.join(SECRET_DIRECTORY_NAME);
            let active = secrets.join("auth-keyring.v1");
            let install =
                secrets.join(".auth-keyring-install-77777777-7777-4777-8777-777777777777.tmp");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            let old_active = fs::read(&active).expect("verify-only active keyring");
            assert_eq!(
                actor
                    .prepare_retire(retire_preparation(&root))
                    .await
                    .expect("prepared retire key install"),
                AuthRetirePrepareOutcome::Prepared
            );
            let reservation = find_only_reservation(&secrets, ".auth-transition-retire-");
            let staged =
                fs::read(reservation.join("staged-keyring")).expect("retired staged keyring");
            assert_eq!(
                actor
                    .commit_retire_source()
                    .await
                    .expect("committed retire source"),
                AuthRetireSourceOutcome::Committed
            );
            let source_after = planned_source_snapshot(&database);

            let failure = actor
                .start_install_retire_active_key_with_fault(fault)
                .expect("admitted retire key install")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_after);
            actor
                .shutdown()
                .await
                .expect("joined poisoned retire install actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh retire install reconciliation"),
                AuthRetireReconciliation::RetireForwardOnly(expected)
            );
            match expected {
                AuthRetireForwardPhase::InstallTempExact => {
                    assert_eq!(fs::read(&active).expect("old active retained"), old_active);
                    assert_eq!(fs::read(&install).expect("new install temp"), staged);
                }
                AuthRetireForwardPhase::AwaitingOldActiveTempRemoval => {
                    assert_eq!(fs::read(&active).expect("new active retained"), staged);
                    assert_eq!(fs::read(&install).expect("old active temp"), old_active);
                }
                AuthRetireForwardPhase::AwaitingFinalDbCas => {
                    assert_eq!(fs::read(&active).expect("new active retained"), staged);
                    assert!(!install.exists());
                }
                _ => panic!("unexpected retire install recovery phase"),
            }
            assert_eq!(
                fresh_actor
                    .install_retire_active_key()
                    .await
                    .expect("resumed retire key install"),
                if expected == AuthRetireForwardPhase::AwaitingFinalDbCas {
                    AuthRetireActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
                } else {
                    AuthRetireActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
                }
            );
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("terminal retire install reconciliation"),
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingFinalDbCas
                )
            );
            assert_eq!(fs::read(&active).expect("terminal retired active"), staged);
            assert!(!install.exists());
            assert_eq!(planned_source_snapshot(&database), source_after);
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh retire install actor");
        }
    }

    #[tokio::test]
    async fn retire_final_lifecycle_commit_uncertainty_is_freshly_classified() {
        for (fault, expected_outcome, expected_phase) in [
            (
                AuthPlannedRotationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                AuthRetireFinalLifecycleOutcome::ActivatedAwaitingCleanup,
                AuthRetireForwardPhase::AwaitingCleanupRename,
            ),
            (
                AuthPlannedRotationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                AuthRetireFinalLifecycleOutcome::ConfirmedNotActivated,
                AuthRetireForwardPhase::AwaitingFinalDbCas,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            advance_retire_to_awaiting_final_db_cas(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("retired active before final fault");

            assert_eq!(
                actor
                    .start_commit_retire_final_lifecycle_with_fault(fault)
                    .expect("admitted retire final lifecycle")
                    .await
                    .expect("classified retire final lifecycle"),
                expected_outcome
            );
            assert_eq!(
                actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("retire final lifecycle fault reconciliation"),
                AuthRetireReconciliation::RetireForwardOnly(expected_phase)
            );
            assert_eq!(
                fs::read(&active).expect("retired active preserved"),
                active_before
            );
            let source_after = planned_source_snapshot(&database);
            if expected_phase == AuthRetireForwardPhase::AwaitingCleanupRename {
                assert_eq!(source_after.lifecycle.0, "active");
                assert_eq!(source_after.lifecycle.1, source_before.lifecycle.1 + 1);
            } else {
                assert_eq!(source_after, source_before);
                assert_eq!(
                    actor
                        .commit_retire_final_lifecycle()
                        .await
                        .expect("retried retire final lifecycle"),
                    AuthRetireFinalLifecycleOutcome::ActivatedAwaitingCleanup
                );
            }
            assert!(stores.conversation.report().await.is_ok());
            actor.shutdown().await.expect("joined retire final actor");
        }
    }

    #[tokio::test]
    async fn retire_cleanup_faults_resume_in_exact_deletion_order() {
        for (fault, expected) in [
            (
                AuthPlannedRotationCleanupTestFault::Rename,
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupStagedRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Staged,
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupPreparedRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Prepared,
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupMetadataRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Metadata,
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupDirectoryRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Directory,
                AuthRetireReconciliation::CleanActiveOnly,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            advance_retire_to_awaiting_cleanup(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("retired active before cleanup fault");

            let failure = actor
                .start_cleanup_retire_with_fault(fault)
                .expect("admitted retire cleanup")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(
                fs::read(&active).expect("retired active preserved"),
                active_before
            );
            actor
                .shutdown()
                .await
                .expect("joined poisoned retire cleanup actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh retire cleanup reconciliation"),
                expected
            );
            assert_eq!(
                fresh_actor
                    .cleanup_retire()
                    .await
                    .expect("resumed retire cleanup"),
                if expected == AuthRetireReconciliation::CleanActiveOnly {
                    AuthRetireCleanupOutcome::AlreadyCompleted
                } else {
                    AuthRetireCleanupOutcome::Completed
                }
            );
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("terminal retire cleanup reconciliation"),
                AuthRetireReconciliation::CleanActiveOnly
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(
                fs::read(&active).expect("terminal retired active"),
                active_before
            );
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh retire cleanup actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_source_commit_is_exact_replayable_and_keeps_active_key_unchanged() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("active bytes before planned source");
        let active_inode_before = fs::symlink_metadata(&active)
            .expect("active metadata before planned source")
            .ino();
        let preparation = planned_rotation_preparation(&root);
        let result_kid = preparation.source_expectation().result_kid().to_owned();

        assert_eq!(
            actor
                .prepare_planned_rotation(preparation)
                .await
                .expect("prepared planned source"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_planned_rotation_source()
                .await
                .expect("committed planned source"),
            AuthPlannedRotationSourceOutcome::Committed
        );
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("planned forward reconciliation"),
            AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingInstallTemp
            )
        );
        assert_eq!(
            actor
                .commit_planned_rotation_source()
                .await
                .expect("replayed planned source"),
            AuthPlannedRotationSourceOutcome::AlreadyCommitted
        );
        assert_eq!(
            actor
                .rollback_planned_rotation_pre_source()
                .await
                .expect("planned rollback rejected after source"),
            AuthPlannedRotationRollbackOutcome::NotRollbackable(
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingInstallTemp
                )
            )
        );

        let source_after = planned_source_snapshot(&database);
        assert_eq!(source_after.lifecycle.0, "transitioning");
        assert_eq!(source_after.lifecycle.1, source_before.lifecycle.1 + 1);
        assert_eq!(
            source_after.lifecycle.2.as_deref(),
            Some(result_kid.as_str())
        );
        assert_eq!(source_after.lifecycle.3.as_deref(), Some("planned"));
        assert_eq!(source_after.lifecycle.4, Some(PLANNED_TRANSITION.to_vec()));
        assert_eq!(
            source_after.lifecycle.5,
            source_before.lifecycle.5.map(|version| version + 1)
        );
        assert_eq!(source_after.audit_count, source_before.audit_count + 1);
        assert_eq!(source_after.account, source_before.account);
        assert_eq!(source_after.password, source_before.password);
        assert_eq!(source_after.recovery, source_before.recovery);
        assert_eq!(
            fs::read(&active).expect("active bytes after planned source"),
            active_before
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("active metadata after planned source")
                .ino(),
            active_inode_before
        );
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined planned source actor");
    }

    #[tokio::test]
    async fn planned_rotation_source_durability_faults_preserve_pre_source_evidence() {
        for fault in [
            AuthPlannedRotationSourceDurabilityTestFault::Metadata,
            AuthPlannedRotationSourceDurabilityTestFault::Staged,
            AuthPlannedRotationSourceDurabilityTestFault::Prepared,
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("active bytes");
            assert_eq!(
                actor
                    .prepare_planned_rotation(planned_rotation_preparation(&root))
                    .await
                    .expect("prepared planned source fixture"),
                AuthPlannedRotationPrepareOutcome::Prepared
            );

            let failure = actor
                .start_commit_planned_rotation_source_with_durability_fault(fault)
                .expect("admitted planned source")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            actor.shutdown().await.expect("joined poisoned actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh prepared reconciliation"),
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::Prepared,
                    recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
                }
            );
            assert_eq!(
                fresh_actor
                    .commit_planned_rotation_source()
                    .await
                    .expect("fresh planned source commit"),
                AuthPlannedRotationSourceOutcome::Committed
            );
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh planned forward reconciliation"),
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingInstallTemp
                )
            );
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh planned source actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_source_commit_uncertainty_is_classified_from_fresh_state() {
        for (fault, expected_outcome, expected_reconciliation) in [
            (
                AuthPlannedRotationSourceMutationTestFault::AfterCommitResponseLoss,
                AuthPlannedRotationSourceOutcome::Committed,
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingInstallTemp,
                ),
            ),
            (
                AuthPlannedRotationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                AuthPlannedRotationSourceOutcome::ConfirmedNotCommitted,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::Prepared,
                    recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
                },
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("active bytes");
            assert_eq!(
                actor
                    .prepare_planned_rotation(planned_rotation_preparation(&root))
                    .await
                    .expect("prepared planned source fixture"),
                AuthPlannedRotationPrepareOutcome::Prepared
            );

            assert_eq!(
                actor
                    .start_commit_planned_rotation_source_with_fault(fault)
                    .expect("admitted planned source")
                    .await
                    .expect("classified planned source result"),
                expected_outcome
            );
            assert_eq!(
                actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("planned source reconciliation"),
                expected_reconciliation
            );
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            let source_after = planned_source_snapshot(&database);
            if expected_outcome == AuthPlannedRotationSourceOutcome::Committed {
                assert_eq!(source_after.lifecycle.0, "transitioning");
                assert_eq!(source_after.audit_count, source_before.audit_count + 1);
            } else {
                assert_eq!(source_after, source_before);
            }
            assert!(stores.conversation.report().await.is_ok());
            actor.shutdown().await.expect("joined planned source actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_active_key_exchange_is_exact_replayable_and_preserves_forward_state()
    {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let install = secrets.join(PLANNED_INSTALL_NAME);
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        let old_active = fs::read(&active).expect("old active keyring");
        let source_before = planned_source_snapshot(&database);

        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("prepared planned key install"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        let reservation = find_only_reservation(&secrets, ".auth-transition-planned-");
        let staged = fs::read(reservation.join("staged-keyring")).expect("planned staged keyring");
        assert_ne!(staged, old_active);
        assert_eq!(
            actor
                .commit_planned_rotation_source()
                .await
                .expect("committed planned source"),
            AuthPlannedRotationSourceOutcome::Committed
        );
        let source_after = planned_source_snapshot(&database);

        assert_eq!(
            actor
                .install_planned_rotation_active_key()
                .await
                .expect("installed planned active key"),
            AuthPlannedRotationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
        assert_eq!(fs::read(&active).expect("new active keyring"), staged);
        assert!(!install.exists());
        assert_eq!(planned_source_snapshot(&database), source_after);
        assert_ne!(source_after, source_before);
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("planned installed reconciliation"),
            AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas
            )
        );
        assert_eq!(
            actor
                .install_planned_rotation_active_key()
                .await
                .expect("replayed planned active install"),
            AuthPlannedRotationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
        );
        assert_eq!(
            format!(
                "{:?}",
                AuthPlannedRotationActiveKeyInstallOutcome::NotInstallable(
                    AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem
                    )
                )
            ),
            "AuthPlannedRotationActiveKeyInstallOutcome::NotInstallable([REDACTED])"
        );
        assert!(stores.conversation.report().await.is_ok());
        actor
            .shutdown()
            .await
            .expect("joined planned install actor");
    }

    #[tokio::test]
    async fn planned_rotation_active_key_install_faults_resume_from_exact_durable_phase() {
        for (fault, expected) in [
            (
                AuthPlannedRotationActiveKeyInstallTestFault::InstallTempDurable,
                AuthPlannedRotationForwardPhase::InstallTempExact,
            ),
            (
                AuthPlannedRotationActiveKeyInstallTestFault::ExchangeDurable,
                AuthPlannedRotationForwardPhase::AwaitingOldActiveTempRemoval,
            ),
            (
                AuthPlannedRotationActiveKeyInstallTestFault::OldActiveTempRemoved,
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let secrets = root.join(SECRET_DIRECTORY_NAME);
            let active = secrets.join("auth-keyring.v1");
            let install = secrets.join(PLANNED_INSTALL_NAME);
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            let old_active = fs::read(&active).expect("old active keyring");
            assert_eq!(
                actor
                    .prepare_planned_rotation(planned_rotation_preparation(&root))
                    .await
                    .expect("prepared planned key install"),
                AuthPlannedRotationPrepareOutcome::Prepared
            );
            let reservation = find_only_reservation(&secrets, ".auth-transition-planned-");
            let staged =
                fs::read(reservation.join("staged-keyring")).expect("planned staged keyring");
            assert_eq!(
                actor
                    .commit_planned_rotation_source()
                    .await
                    .expect("committed planned source"),
                AuthPlannedRotationSourceOutcome::Committed
            );
            let source_after = planned_source_snapshot(&database);

            let failure = actor
                .start_install_planned_rotation_active_key_with_fault(fault)
                .expect("admitted planned key install")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_after);
            actor
                .shutdown()
                .await
                .expect("joined poisoned install actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh planned install reconciliation"),
                AuthPlannedRotationReconciliation::PlannedForwardOnly(expected)
            );
            match expected {
                AuthPlannedRotationForwardPhase::InstallTempExact => {
                    assert_eq!(fs::read(&active).expect("old active retained"), old_active);
                    assert_eq!(fs::read(&install).expect("new install temp"), staged);
                }
                AuthPlannedRotationForwardPhase::AwaitingOldActiveTempRemoval => {
                    assert_eq!(fs::read(&active).expect("new active retained"), staged);
                    assert_eq!(fs::read(&install).expect("old active temp"), old_active);
                }
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas => {
                    assert_eq!(fs::read(&active).expect("new active retained"), staged);
                    assert!(!install.exists());
                }
                _ => panic!("unexpected planned install recovery phase"),
            }
            assert_eq!(
                fresh_actor
                    .install_planned_rotation_active_key()
                    .await
                    .expect("resumed planned key install"),
                if expected == AuthPlannedRotationForwardPhase::AwaitingFinalDbCas {
                    AuthPlannedRotationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
                } else {
                    AuthPlannedRotationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
                }
            );
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("terminal planned install reconciliation"),
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingFinalDbCas
                )
            );
            assert_eq!(fs::read(&active).expect("terminal new active"), staged);
            assert!(!install.exists());
            assert_eq!(planned_source_snapshot(&database), source_after);
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh planned install actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_final_lifecycle_is_exact_replayable_and_preserves_auth_source() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_awaiting_final_db_cas(&actor, &root).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("planned active before final CAS");
        let active_inode_before = fs::symlink_metadata(&active)
            .expect("planned active metadata before final CAS")
            .ino();

        assert_eq!(
            actor
                .commit_planned_rotation_final_lifecycle()
                .await
                .expect("committed planned final lifecycle"),
            AuthPlannedRotationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("planned final lifecycle reconciliation"),
            AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingCleanupRename
            )
        );
        assert_eq!(
            actor
                .commit_planned_rotation_final_lifecycle()
                .await
                .expect("replayed planned final lifecycle"),
            AuthPlannedRotationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup
        );

        let source_after = planned_source_snapshot(&database);
        assert_eq!(source_after.lifecycle.0, "active");
        assert_eq!(source_after.lifecycle.1, source_before.lifecycle.1 + 1);
        assert_eq!(source_after.lifecycle.2, source_before.lifecycle.2);
        assert_eq!(source_after.lifecycle.3, None);
        assert_eq!(source_after.lifecycle.4, None);
        assert_eq!(source_after.lifecycle.5, source_before.lifecycle.5);
        assert_eq!(source_after.lifecycle.6, source_before.lifecycle.6);
        assert_eq!(source_after.account, source_before.account);
        assert_eq!(source_after.password, source_before.password);
        assert_eq!(source_after.recovery, source_before.recovery);
        assert_eq!(source_after.audit_count, source_before.audit_count);
        assert_eq!(
            fs::read(&active).expect("planned active after final CAS"),
            active_before
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("planned active metadata after final CAS")
                .ino(),
            active_inode_before
        );
        assert_eq!(
            format!(
                "{:?}",
                AuthPlannedRotationFinalLifecycleOutcome::NotActivatable(
                    AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem
                    )
                )
            ),
            "AuthPlannedRotationFinalLifecycleOutcome::NotActivatable([REDACTED])"
        );
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined planned final actor");
    }

    #[tokio::test]
    async fn planned_rotation_final_lifecycle_commit_uncertainty_is_freshly_classified() {
        for (fault, expected_outcome, expected_phase) in [
            (
                AuthPlannedRotationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                AuthPlannedRotationFinalLifecycleOutcome::ActivatedAwaitingCleanup,
                AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
            ),
            (
                AuthPlannedRotationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                AuthPlannedRotationFinalLifecycleOutcome::ConfirmedNotActivated,
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_awaiting_final_db_cas(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("planned active before final fault");

            assert_eq!(
                actor
                    .start_commit_planned_rotation_final_lifecycle_with_fault(fault)
                    .expect("admitted planned final lifecycle")
                    .await
                    .expect("classified planned final lifecycle"),
                expected_outcome
            );
            assert_eq!(
                actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("planned final lifecycle fault reconciliation"),
                AuthPlannedRotationReconciliation::PlannedForwardOnly(expected_phase)
            );
            assert_eq!(
                fs::read(&active).expect("planned active preserved"),
                active_before
            );
            let source_after = planned_source_snapshot(&database);
            if expected_phase == AuthPlannedRotationForwardPhase::AwaitingCleanupRename {
                assert_eq!(source_after.lifecycle.0, "active");
                assert_eq!(source_after.lifecycle.1, source_before.lifecycle.1 + 1);
            } else {
                assert_eq!(source_after, source_before);
                assert_eq!(
                    actor
                        .commit_planned_rotation_final_lifecycle()
                        .await
                        .expect("retried planned final lifecycle"),
                    AuthPlannedRotationFinalLifecycleOutcome::ActivatedAwaitingCleanup
                );
            }
            assert!(stores.conversation.report().await.is_ok());
            actor.shutdown().await.expect("joined planned final actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_cleanup_is_exact_replayable_and_preserves_terminal_key_and_source() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_awaiting_cleanup(&actor, &root).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("planned active before cleanup");
        let active_inode_before = fs::symlink_metadata(&active)
            .expect("planned active metadata before cleanup")
            .ino();

        assert_eq!(
            actor
                .cleanup_planned_rotation()
                .await
                .expect("cleaned planned rotation"),
            AuthPlannedRotationCleanupOutcome::Completed
        );
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("terminal planned reconciliation"),
            AuthPlannedRotationReconciliation::PlannedRotationComplete
        );
        assert_eq!(
            actor
                .cleanup_planned_rotation()
                .await
                .expect("replayed planned cleanup"),
            AuthPlannedRotationCleanupOutcome::AlreadyCompleted
        );
        assert_eq!(planned_source_snapshot(&database), source_before);
        assert_eq!(
            fs::read(&active).expect("planned active after cleanup"),
            active_before
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("planned active metadata after cleanup")
                .ino(),
            active_inode_before
        );
        let retained_names: Vec<OsString> = fs::read_dir(&secrets)
            .expect("terminal secret inventory")
            .map(|entry| entry.expect("terminal secret entry").file_name())
            .collect();
        assert_eq!(retained_names.len(), 2);
        assert!(retained_names.contains(&OsString::from("auth-keyring.v1")));
        assert!(retained_names.contains(&OsString::from(AUTH_LOCK_FILE_NAME)));
        assert_eq!(
            format!(
                "{:?}",
                AuthPlannedRotationCleanupOutcome::NotCleanable(
                    AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem
                    )
                )
            ),
            "AuthPlannedRotationCleanupOutcome::NotCleanable([REDACTED])"
        );
        assert!(stores.conversation.report().await.is_ok());
        actor
            .shutdown()
            .await
            .expect("joined planned cleanup actor");
    }

    #[tokio::test]
    async fn planned_rotation_cleanup_faults_resume_in_exact_deletion_order() {
        for (fault, expected) in [
            (
                AuthPlannedRotationCleanupTestFault::Rename,
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupStagedRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Staged,
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupPreparedRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Prepared,
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupMetadataRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Metadata,
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupDirectoryRemoval,
                ),
            ),
            (
                AuthPlannedRotationCleanupTestFault::Directory,
                AuthPlannedRotationReconciliation::PlannedRotationComplete,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_awaiting_cleanup(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("planned active before cleanup fault");

            let failure = actor
                .start_cleanup_planned_rotation_with_fault(fault)
                .expect("admitted planned cleanup")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(
                fs::read(&active).expect("planned active preserved"),
                active_before
            );
            actor
                .shutdown()
                .await
                .expect("joined poisoned cleanup actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh planned cleanup reconciliation"),
                expected
            );
            assert_eq!(
                fresh_actor
                    .cleanup_planned_rotation()
                    .await
                    .expect("resumed planned cleanup"),
                if expected == AuthPlannedRotationReconciliation::PlannedRotationComplete {
                    AuthPlannedRotationCleanupOutcome::AlreadyCompleted
                } else {
                    AuthPlannedRotationCleanupOutcome::Completed
                }
            );
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("terminal planned cleanup reconciliation"),
                AuthPlannedRotationReconciliation::PlannedRotationComplete
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(
                fs::read(&active).expect("terminal planned active"),
                active_before
            );
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh planned cleanup actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_preparation_durability_faults_have_exact_fresh_actor_phases() {
        for (fault, expected) in [
            (
                AuthPlannedRotationPrepareTestFault::Reservation,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::ReservationOnly,
                    recovery: AuthPlannedRotationRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthPlannedRotationPrepareTestFault::Metadata,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::MetadataComplete,
                    recovery: AuthPlannedRotationRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthPlannedRotationPrepareTestFault::Staged,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::StagedComplete,
                    recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
                },
            ),
            (
                AuthPlannedRotationPrepareTestFault::Prepared,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::Prepared,
                    recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
                },
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("active bytes");

            let failure = actor
                .start_prepare_planned_rotation_with_fault(
                    planned_rotation_preparation(&root),
                    fault,
                )
                .expect("admitted planned preparation")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            actor.shutdown().await.expect("joined poisoned actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh planned reconciliation"),
                expected
            );
            assert_eq!(
                fresh_actor
                    .rollback_planned_rotation_pre_source()
                    .await
                    .expect("fresh planned rollback"),
                AuthPlannedRotationRollbackOutcome::RolledBack
            );
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh terminal reconciliation"),
                AuthPlannedRotationReconciliation::CleanActive
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh planned actor");
        }
    }

    #[tokio::test]
    async fn retire_preparation_durability_faults_have_exact_fresh_actor_phases() {
        for (fault, expected) in [
            (
                AuthRetirePrepareTestFault::Reservation,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::ReservationOnly,
                    recovery: AuthRetireRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthRetirePrepareTestFault::Metadata,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::MetadataComplete,
                    recovery: AuthRetireRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthRetirePrepareTestFault::Staged,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::StagedComplete,
                    recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
                },
            ),
            (
                AuthRetirePrepareTestFault::Prepared,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::Prepared,
                    recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
                },
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("verify-only active bytes");

            let failure = actor
                .start_prepare_retire_with_fault(retire_preparation(&root), fault)
                .expect("admitted retire preparation")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(
                actor.revalidate().await.unwrap_err(),
                AuthMaintenanceActorError::Poisoned
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            actor
                .shutdown()
                .await
                .expect("joined poisoned retire actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh retire reconciliation"),
                expected
            );
            assert_eq!(
                fresh_actor
                    .rollback_retire_pre_source()
                    .await
                    .expect("fresh retire rollback"),
                AuthRetireRollbackOutcome::RolledBack
            );
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh retire terminal"),
                AuthRetireReconciliation::ReadyToRetire
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh retire actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_reconciliation_and_rollback_cover_all_six_pre_source_phases() {
        for phase in [
            AuthPlannedRotationPreSourcePhase::ReservationOnly,
            AuthPlannedRotationPreSourcePhase::MetadataIncomplete,
            AuthPlannedRotationPreSourcePhase::MetadataComplete,
            AuthPlannedRotationPreSourcePhase::StagedIncomplete,
            AuthPlannedRotationPreSourcePhase::StagedComplete,
            AuthPlannedRotationPreSourcePhase::Prepared,
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("active bytes");
            let preparation = planned_rotation_preparation(&root);
            write_planned_pre_source_reservation(&root, &preparation, phase);
            let recovery = if matches!(
                phase,
                AuthPlannedRotationPreSourcePhase::StagedComplete
                    | AuthPlannedRotationPreSourcePhase::Prepared
            ) {
                AuthPlannedRotationRecovery::ResumeOrRollbackCandidate
            } else {
                AuthPlannedRotationRecovery::RollbackOnlyCandidate
            };
            assert_eq!(
                actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("planned pre-source phase"),
                AuthPlannedRotationReconciliation::PlannedPreSource { phase, recovery }
            );
            assert_eq!(
                actor
                    .rollback_planned_rotation_pre_source()
                    .await
                    .expect("planned phase rollback"),
                AuthPlannedRotationRollbackOutcome::RolledBack
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            assert!(stores.conversation.report().await.is_ok());
            actor.shutdown().await.expect("joined phase actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_rollback_faults_resume_in_reverse_creation_order() {
        for (fault, expected) in [
            (
                AuthPlannedRotationRollbackTestFault::Prepared,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::StagedComplete,
                    recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
                },
            ),
            (
                AuthPlannedRotationRollbackTestFault::Staged,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::MetadataComplete,
                    recovery: AuthPlannedRotationRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthPlannedRotationRollbackTestFault::Metadata,
                AuthPlannedRotationReconciliation::PlannedPreSource {
                    phase: AuthPlannedRotationPreSourcePhase::ReservationOnly,
                    recovery: AuthPlannedRotationRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthPlannedRotationRollbackTestFault::Directory,
                AuthPlannedRotationReconciliation::CleanActive,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("active bytes");
            assert_eq!(
                actor
                    .prepare_planned_rotation(planned_rotation_preparation(&root))
                    .await
                    .expect("prepared planned rollback fixture"),
                AuthPlannedRotationPrepareOutcome::Prepared
            );

            let failure = actor
                .start_rollback_planned_rotation_pre_source_with_fault(fault)
                .expect("admitted planned rollback")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            actor.shutdown().await.expect("joined poisoned actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_planned_rotation_reconciliation()
                    .await
                    .expect("fresh planned rollback phase"),
                expected
            );
            let replay = fresh_actor
                .rollback_planned_rotation_pre_source()
                .await
                .expect("resumed planned rollback");
            assert_eq!(
                replay,
                if expected == AuthPlannedRotationReconciliation::CleanActive {
                    AuthPlannedRotationRollbackOutcome::AlreadyClean
                } else {
                    AuthPlannedRotationRollbackOutcome::RolledBack
                }
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh planned rollback actor");
        }
    }

    #[tokio::test]
    async fn retire_rollback_faults_resume_in_reverse_creation_order() {
        for (fault, expected) in [
            (
                AuthRetireRollbackTestFault::Prepared,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::StagedComplete,
                    recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
                },
            ),
            (
                AuthRetireRollbackTestFault::Staged,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::MetadataComplete,
                    recovery: AuthRetireRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthRetireRollbackTestFault::Metadata,
                AuthRetireReconciliation::RetirePreSource {
                    phase: AuthRetirePreSourcePhase::ReservationOnly,
                    recovery: AuthRetireRecovery::RollbackOnlyCandidate,
                },
            ),
            (
                AuthRetireRollbackTestFault::Directory,
                AuthRetireReconciliation::ReadyToRetire,
            ),
        ] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
            let active = root.join(SECRET_DIRECTORY_NAME).join("auth-keyring.v1");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            let source_before = planned_source_snapshot(&database);
            let active_before = fs::read(&active).expect("verify-only active bytes");
            assert_eq!(
                actor
                    .prepare_retire(retire_preparation(&root))
                    .await
                    .expect("prepared retire rollback fixture"),
                AuthRetirePrepareOutcome::Prepared
            );

            let failure = actor
                .start_rollback_retire_pre_source_with_fault(fault)
                .expect("admitted retire rollback")
                .await
                .unwrap_err();
            assert!(matches!(
                failure,
                AuthMaintenanceActorError::Binding(AuthStoreBindingError::Filesystem(
                    SecretFsError::Io(io::ErrorKind::Other)
                ))
            ));
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert_eq!(fs::read(&active).expect("active preserved"), active_before);
            actor
                .shutdown()
                .await
                .expect("joined poisoned retire actor");
            drop(stores);

            let (fresh_actor, fresh_stores) = actor_and_stores(&root).await;
            assert_eq!(
                fresh_actor
                    .inspect_retire_reconciliation()
                    .await
                    .expect("fresh retire rollback phase"),
                expected
            );
            let replay = fresh_actor
                .rollback_retire_pre_source()
                .await
                .expect("resumed retire rollback");
            assert_eq!(
                replay,
                if expected == AuthRetireReconciliation::ReadyToRetire {
                    AuthRetireRollbackOutcome::AlreadyReady
                } else {
                    AuthRetireRollbackOutcome::RolledBack
                }
            );
            assert_eq!(planned_source_snapshot(&database), source_before);
            assert!(fresh_stores.conversation.report().await.is_ok());
            fresh_actor
                .shutdown()
                .await
                .expect("joined fresh retire rollback actor");
        }
    }

    #[tokio::test]
    async fn retire_rejects_metadata_source_and_current_key_mismatches_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("verify-only active bytes");

        for case in 0..6 {
            let mut input = retire_input();
            match case {
                0 => input.expected_lifecycle_revision = 5,
                1 => {
                    input.expected_lifecycle_updated_at_micros =
                        SourceTimestampMicros::new(SOURCE_AT_MICROS as u64 + 12)
                            .expect("mismatched lifecycle timestamp")
                }
                2 => input.credential_version = 2,
                3 => input.account_revision = 2,
                4 => input.password_credential_revision = 2,
                5 => input.recovery_credential_revision = 2,
                _ => unreachable!(),
            }
            assert_eq!(
                actor
                    .prepare_retire(retire_preparation_with_input(&root, input))
                    .await
                    .expect("typed retire mismatch"),
                AuthRetirePrepareOutcome::PreconditionNotReady(AuthRetireReconciliation::Blocked(
                    AuthRetireBlocker::InconsistentDbFilesystem,
                ))
            );
        }

        let unrelated_current = Keyring::from_test_seeds(
            2,
            SOURCE_AT_MICROS as u64 + 10,
            [0x51; 32],
            Some((SOURCE_AT_MICROS as u64 - 1, [0x31; 32])),
        )
        .expect("unrelated verify-only keyring");
        let unrelated_preparation =
            RetirePreparationV1::from_current_keyring(retire_input(), &unrelated_current)
                .expect("unrelated retire preparation");
        assert_eq!(
            actor
                .prepare_retire(unrelated_preparation)
                .await
                .expect("typed current key mismatch"),
            AuthRetirePrepareOutcome::PreconditionNotReady(AuthRetireReconciliation::Blocked(
                AuthRetireBlocker::InconsistentDbFilesystem,
            ))
        );
        assert_eq!(planned_source_snapshot(&database), source_before);
        assert_eq!(fs::read(&active).expect("active unchanged"), active_before);
        assert!(
            fs::read_dir(&secrets)
                .expect("secret inventory")
                .all(|entry| !entry
                    .expect("secret entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".auth-transition-retire-"))
        );
        assert!(stores.conversation.report().await.is_ok());
        actor
            .shutdown()
            .await
            .expect("joined retire mismatch actor");
    }

    #[tokio::test]
    async fn retire_rejects_unknown_changed_and_hard_link_artifacts_without_cleanup() {
        for case in ["unknown", "changed", "hard-link"] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            advance_planned_rotation_to_complete(&actor, &root).await;
            assert_eq!(
                actor
                    .prepare_retire(retire_preparation(&root))
                    .await
                    .expect("prepared retire blocker fixture"),
                AuthRetirePrepareOutcome::Prepared
            );
            let reservation = root
                .join(SECRET_DIRECTORY_NAME)
                .join(".auth-transition-retire-77777777-7777-4777-8777-777777777777");
            match case {
                "unknown" => owner_file(&reservation.join("unknown"), b"preserve"),
                "changed" => {
                    let current = current_active_keyring(&root).encode();
                    owner_file(&reservation.join("staged-keyring"), current.expose_secret());
                }
                "hard-link" => fs::hard_link(
                    reservation.join("staged-keyring"),
                    reservation.join("linked-staged"),
                )
                .expect("retire staged hard link"),
                _ => unreachable!(),
            }
            let injected = reservation_snapshot(&reservation);

            if case == "hard-link" {
                assert!(actor.inspect_retire_reconciliation().await.is_err());
                assert!(matches!(
                    stores.conversation.report().await,
                    Err(StoreError::OperationPoisoned {
                        kind: StoreKind::Conversation
                    })
                ));
            } else {
                assert!(matches!(
                    actor
                        .rollback_retire_pre_source()
                        .await
                        .expect("typed retire blocker"),
                    AuthRetireRollbackOutcome::NotRollbackable(AuthRetireReconciliation::Blocked(
                        _
                    ))
                ));
                assert!(stores.conversation.report().await.is_ok());
            }
            assert_eq!(reservation_snapshot(&reservation), injected);
            actor.shutdown().await.expect("joined retire blocker actor");
        }
    }

    #[tokio::test]
    async fn retire_pre_mutation_source_drift_is_rejected_without_deletion() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-retire-77777777-7777-4777-8777-777777777777");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        assert_eq!(
            actor
                .prepare_retire(retire_preparation(&root))
                .await
                .expect("prepared retire drift fixture"),
            AuthRetirePrepareOutcome::Prepared
        );
        let before = reservation_snapshot(&reservation);
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_retire_pre_source_with_before_mutation_gate(gate.clone())
            .expect("admitted retire pre-mutation drift rollback");
        gate.wait_until_reached();
        RawConnection::open(&database)
            .expect("retire source drift writer")
            .execute(
                "UPDATE auth_accounts
                 SET account_revision = account_revision + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("retire source revision drift");
        gate.resume();
        assert!(matches!(
            run.await.expect("typed retire drift result"),
            AuthRetireRollbackOutcome::NotRollbackable(AuthRetireReconciliation::Blocked(_))
        ));
        assert_eq!(reservation_snapshot(&reservation), before);
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined retire drift actor");
    }

    #[tokio::test]
    async fn retire_post_mutation_drift_preserves_evidence_and_poisons() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-retire-77777777-7777-4777-8777-777777777777");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        assert_eq!(
            actor
                .prepare_retire(retire_preparation(&root))
                .await
                .expect("prepared retire post-mutation drift fixture"),
            AuthRetirePrepareOutcome::Prepared
        );
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_retire_pre_source_with_after_first_mutation_gate(gate.clone())
            .expect("admitted retire post-mutation drift rollback");
        gate.wait_until_reached();
        assert!(!reservation.join("prepared").exists());
        assert!(reservation.join("staged-keyring").exists());
        RawConnection::open(&database)
            .expect("retire post-mutation drift writer")
            .execute(
                "UPDATE auth_accounts
                 SET account_revision = account_revision + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("retire post-mutation source revision drift");
        gate.resume();
        assert!(run.await.is_err());
        assert!(reservation.join("metadata").exists());
        assert!(reservation.join("staged-keyring").exists());
        assert!(!reservation.join("prepared").exists());
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending retire layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        actor
            .shutdown()
            .await
            .expect("joined poisoned retire drift actor");
    }

    #[tokio::test]
    async fn retire_read_only_reconciliation_detects_source_drift_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-retire-77777777-7777-4777-8777-777777777777");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        actor.shutdown().await.expect("joined retire setup actor");
        drop(stores);

        let (context, stores) = owned_context_and_stores(&root).await;
        let preparation = retire_preparation(&root);
        assert_eq!(
            context
                .prepare_retire(&preparation)
                .expect("direct retire preparation"),
            AuthRetirePrepareOutcome::Prepared
        );
        let before = reservation_snapshot(&reservation);
        let drift_database = database.clone();
        assert_eq!(
            context
                .inspect_retire_reconciliation_with_checkpoints(
                    move || {
                        RawConnection::open(&drift_database)
                            .expect("retire read-only drift writer")
                            .execute(
                                "UPDATE auth_accounts
                                 SET account_revision = account_revision + 1
                                 WHERE singleton = 1",
                                [],
                            )
                            .expect("retire read-only source drift");
                    },
                    || {},
                )
                .unwrap_err(),
            AuthStoreBindingError::ConversationStoreChanged
        );
        assert_eq!(reservation_snapshot(&reservation), before);
        assert!(stores.conversation.report().await.is_ok());
        drop(context);
    }

    #[tokio::test]
    async fn retire_reservation_inode_aba_is_rejected_before_deletion() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-retire-77777777-7777-4777-8777-777777777777");
        let retained = directory.path().join("retained-retire-reservation");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        assert_eq!(
            actor
                .prepare_retire(retire_preparation(&root))
                .await
                .expect("prepared retire ABA fixture"),
            AuthRetirePrepareOutcome::Prepared
        );
        let original = reservation_snapshot(&reservation);
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_retire_pre_source_with_before_mutation_gate(gate.clone())
            .expect("admitted retire ABA rollback");
        gate.wait_until_reached();
        fs::rename(&reservation, &retained).expect("retain original retire reservation inode");
        fs::create_dir(&reservation).expect("replacement retire reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))
            .expect("replacement retire reservation mode");
        for entry in &original.entries {
            owner_file(
                &reservation.join(&entry.name),
                entry.bytes.as_deref().expect("known retire file"),
            );
        }
        gate.resume();
        assert!(run.await.is_err());
        let replacement = reservation_snapshot(&reservation);
        let retained_original = reservation_snapshot(&retained);
        assert_eq!(retained_original, original);
        assert_eq!(replacement.mode, 0o700);
        assert_eq!(replacement.entries.len(), original.entries.len());
        for original_entry in &original.entries {
            let replacement_entry = replacement
                .entries
                .iter()
                .find(|entry| entry.name == original_entry.name)
                .expect("replacement retire evidence");
            assert_eq!(replacement_entry.bytes, original_entry.bytes);
            assert_eq!(replacement_entry.mode, original_entry.mode);
        }
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined retire ABA actor");
    }

    #[tokio::test]
    async fn retire_debug_and_errors_redact_key_and_transition_identifiers() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, _stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        let current = current_active_keyring(&root);
        let current_kid = current.active_kid().as_str().to_owned();
        let preparation = retire_preparation(&root);
        let debug = format!(
            "{preparation:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            current.active_kid(),
            AuthRetirePrepareOutcome::PreconditionNotReady(AuthRetireReconciliation::Blocked(
                AuthRetireBlocker::InconsistentDbFilesystem,
            )),
            AuthRetireRollbackOutcome::NotRollbackable(AuthRetireReconciliation::Blocked(
                AuthRetireBlocker::InconsistentDbFilesystem,
            )),
            AuthRetireSourceOutcome::NotPrepared(AuthRetireReconciliation::Blocked(
                AuthRetireBlocker::InconsistentDbFilesystem,
            )),
            AuthRetireActiveKeyInstallOutcome::NotInstallable(AuthRetireReconciliation::Blocked(
                AuthRetireBlocker::InconsistentDbFilesystem,
            )),
            AuthRetireCleanupOutcome::NotCleanable(AuthRetireReconciliation::Blocked(
                AuthRetireBlocker::InconsistentDbFilesystem,
            ))
        );
        assert!(!debug.contains(&current_kid));
        assert!(!debug.contains("77777777-7777-4777-8777-777777777777"));
        assert!(!debug.contains("88888888-8888-4888-8888-888888888888"));
        assert!(debug.contains("[REDACTED]"));
        actor
            .shutdown()
            .await
            .expect("joined retire redaction actor");
    }

    #[tokio::test]
    async fn dropped_retire_preparation_receiver_does_not_cancel_work_or_release_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-retire-77777777-7777-4777-8777-777777777777");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        advance_planned_rotation_to_complete(&actor, &root).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_prepare_retire_with_pre_mutation_gate(retire_preparation(&root), gate.clone())
            .expect("admitted dropped retire preparation");
        gate.wait_until_reached();
        drop(run);
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending retire layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        gate.resume();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !reservation.join("prepared").exists() {
            assert!(
                Instant::now() < deadline,
                "dropped retire preparation did not complete"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            actor
                .inspect_retire_reconciliation()
                .await
                .expect("retire preparation completed after receiver drop"),
            AuthRetireReconciliation::RetirePreSource {
                phase: AuthRetirePreSourcePhase::Prepared,
                recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
            }
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending retire layout after command")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        assert!(stores.conversation.report().await.is_ok());
        actor
            .shutdown()
            .await
            .expect("joined dropped-retire-receiver actor");
        wait_until_lock_available(&root);
    }

    #[tokio::test]
    async fn planned_rotation_rejects_metadata_source_and_current_key_mismatches_without_mutation()
    {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let secrets = root.join(SECRET_DIRECTORY_NAME);
        let active = secrets.join("auth-keyring.v1");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        let source_before = planned_source_snapshot(&database);
        let active_before = fs::read(&active).expect("active bytes");

        for case in 0..6 {
            let mut input = planned_rotation_input();
            match case {
                0 => input.expected_lifecycle_revision = 4,
                1 => {
                    input.expected_lifecycle_updated_at_micros =
                        SourceTimestampMicros::new(SOURCE_AT_MICROS as u64 + 1)
                            .expect("mismatched lifecycle timestamp")
                }
                2 => input.credential_version = 2,
                3 => input.account_revision = 2,
                4 => input.password_credential_revision = 2,
                5 => input.recovery_credential_revision = 2,
                _ => unreachable!(),
            }
            assert_eq!(
                actor
                    .prepare_planned_rotation(
                        planned_rotation_preparation_with_input(&root, input,)
                    )
                    .await
                    .expect("typed planned mismatch"),
                AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                    AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                    )
                )
            );
        }

        let unrelated_current =
            Keyring::from_test_seeds(2, SOURCE_AT_MICROS as u64 - 1, [0x51; 32], None)
                .expect("unrelated active keyring");
        let unrelated_staged = unrelated_current
            .planned_rotation_from_test_seed(SOURCE_AT_MICROS as u64 + 10, [0x52; 32])
            .expect("unrelated staged keyring");
        let unrelated_preparation = PlannedRotationPreparationV1::from_keyrings(
            planned_rotation_input(),
            &unrelated_current,
            unrelated_staged,
        )
        .expect("unrelated planned preparation");
        assert_eq!(
            actor
                .prepare_planned_rotation(unrelated_preparation)
                .await
                .expect("typed current key mismatch"),
            AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                )
            )
        );
        assert_eq!(planned_source_snapshot(&database), source_before);
        assert_eq!(fs::read(&active).expect("active unchanged"), active_before);
        assert!(
            fs::read_dir(&secrets)
                .expect("secret inventory")
                .all(|entry| !entry
                    .expect("secret entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".auth-transition-planned-"))
        );
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined mismatch actor");
    }

    #[tokio::test]
    async fn planned_rotation_rejects_verify_only_unknown_changed_and_hard_link_artifacts() {
        let verify_directory = tempdir().expect("temporary parent");
        let verify_root = verify_directory.path().join("instance");
        let (verify_actor, verify_stores) = actor_and_stores(&verify_root).await;
        advance_initialization_to_clean_active(&verify_actor).await;
        let current = current_active_keyring(&verify_root);
        let overlap = current
            .planned_rotation_from_test_seed(SOURCE_AT_MICROS as u64 + 10, [0x41; 32])
            .expect("verify-only overlap")
            .encode();
        owner_file(
            &verify_root
                .join(SECRET_DIRECTORY_NAME)
                .join("auth-keyring.v1"),
            overlap.expose_secret(),
        );
        assert_eq!(
            verify_actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("verify-only rejection"),
            AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem
            )
        );
        assert!(verify_stores.conversation.report().await.is_ok());
        verify_actor
            .shutdown()
            .await
            .expect("joined verify-only actor");

        for case in ["unknown", "changed", "hard-link"] {
            let directory = tempdir().expect("temporary parent");
            let root = directory.path().join("instance");
            let (actor, stores) = actor_and_stores(&root).await;
            advance_initialization_to_clean_active(&actor).await;
            assert_eq!(
                actor
                    .prepare_planned_rotation(planned_rotation_preparation(&root))
                    .await
                    .expect("prepared blocker fixture"),
                AuthPlannedRotationPrepareOutcome::Prepared
            );
            let reservation = root
                .join(SECRET_DIRECTORY_NAME)
                .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
            match case {
                "unknown" => owner_file(&reservation.join("unknown"), b"preserve"),
                "changed" => {
                    let current = current_active_keyring(&root).encode();
                    owner_file(&reservation.join("staged-keyring"), current.expose_secret());
                }
                "hard-link" => fs::hard_link(
                    reservation.join("staged-keyring"),
                    reservation.join("linked-staged"),
                )
                .expect("staged hard link"),
                _ => unreachable!(),
            }
            let injected = reservation_snapshot(&reservation);

            if case == "hard-link" {
                assert!(
                    actor
                        .inspect_planned_rotation_reconciliation()
                        .await
                        .is_err()
                );
                assert!(matches!(
                    stores.conversation.report().await,
                    Err(StoreError::OperationPoisoned {
                        kind: StoreKind::Conversation
                    })
                ));
            } else {
                assert!(matches!(
                    actor
                        .rollback_planned_rotation_pre_source()
                        .await
                        .expect("typed planned blocker"),
                    AuthPlannedRotationRollbackOutcome::NotRollbackable(
                        AuthPlannedRotationReconciliation::Blocked(_)
                    )
                ));
                assert!(stores.conversation.report().await.is_ok());
            }
            let after = reservation_snapshot(&reservation);
            assert_eq!(after, injected);
            actor.shutdown().await.expect("joined blocker actor");
        }
    }

    #[tokio::test]
    async fn planned_rotation_pre_mutation_source_drift_is_rejected_without_deletion() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("prepared drift fixture"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        let before = reservation_snapshot(&reservation);
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_planned_rotation_pre_source_with_before_mutation_gate(gate.clone())
            .expect("admitted pre-mutation drift rollback");
        gate.wait_until_reached();
        RawConnection::open(&database)
            .expect("source drift writer")
            .execute(
                "UPDATE auth_accounts
                 SET account_revision = account_revision + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("source revision drift");
        gate.resume();
        assert!(matches!(
            run.await.expect("typed drift result"),
            AuthPlannedRotationRollbackOutcome::NotRollbackable(
                AuthPlannedRotationReconciliation::Blocked(_)
            )
        ));
        assert_eq!(reservation_snapshot(&reservation), before);
        assert!(stores.conversation.report().await.is_ok());
        actor.shutdown().await.expect("joined drift actor");
    }

    #[tokio::test]
    async fn planned_rotation_post_mutation_drift_preserves_evidence_and_poisons() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("prepared post-mutation drift fixture"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_planned_rotation_pre_source_with_after_first_mutation_gate(gate.clone())
            .expect("admitted post-mutation drift rollback");
        gate.wait_until_reached();
        assert!(!reservation.join("prepared").exists());
        assert!(reservation.join("staged-keyring").exists());
        RawConnection::open(&database)
            .expect("post-mutation source drift writer")
            .execute(
                "UPDATE auth_accounts
                 SET account_revision = account_revision + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("post-mutation source revision drift");
        gate.resume();
        assert!(run.await.is_err());
        assert!(reservation.join("metadata").exists());
        assert!(reservation.join("staged-keyring").exists());
        assert!(!reservation.join("prepared").exists());
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        actor.shutdown().await.expect("joined poisoned drift actor");
    }

    #[tokio::test]
    async fn planned_rotation_read_only_reconciliation_detects_source_drift_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        actor.shutdown().await.expect("joined setup actor");
        drop(stores);

        let (context, stores) = owned_context_and_stores(&root).await;
        let preparation = planned_rotation_preparation(&root);
        assert_eq!(
            context
                .prepare_planned_rotation(&preparation)
                .expect("direct planned preparation"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        let before = reservation_snapshot(&reservation);
        let drift_database = database.clone();
        assert_eq!(
            context
                .inspect_planned_rotation_reconciliation_with_checkpoints(
                    move || {
                        RawConnection::open(&drift_database)
                            .expect("read-only drift writer")
                            .execute(
                                "UPDATE auth_accounts
                                 SET account_revision = account_revision + 1
                                 WHERE singleton = 1",
                                [],
                            )
                            .expect("read-only source drift");
                    },
                    || {},
                )
                .unwrap_err(),
            AuthStoreBindingError::ConversationStoreChanged
        );
        assert_eq!(reservation_snapshot(&reservation), before);
        assert!(stores.conversation.report().await.is_ok());
        drop(context);
    }

    #[tokio::test]
    async fn planned_rotation_terminal_post_mutation_drift_poisons_without_undoing_drift() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let database = root.join(STORE_DIRECTORY_NAME).join("conversation.sqlite3");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("prepared terminal drift fixture"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_planned_rotation_pre_source_with_after_rollback_gate(gate.clone())
            .expect("admitted terminal drift rollback");
        gate.wait_until_reached();
        assert!(!reservation.exists());
        RawConnection::open(&database)
            .expect("terminal drift writer")
            .execute(
                "UPDATE auth_accounts
                 SET account_revision = account_revision + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("terminal source drift");
        gate.resume();
        assert!(run.await.is_err());
        assert!(!reservation.exists());
        assert_eq!(
            RawConnection::open(&database)
                .expect("terminal drift reader")
                .query_row(
                    "SELECT account_revision FROM auth_accounts WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("terminal account revision"),
            2
        );
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined terminal drift actor");
    }

    #[tokio::test]
    async fn planned_rotation_reservation_inode_aba_is_rejected_before_deletion() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        let retained = directory.path().join("retained-planned-reservation");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        assert_eq!(
            actor
                .prepare_planned_rotation(planned_rotation_preparation(&root))
                .await
                .expect("prepared ABA fixture"),
            AuthPlannedRotationPrepareOutcome::Prepared
        );
        let original = reservation_snapshot(&reservation);
        let gate = ActorTestGate::new();
        let run = actor
            .start_rollback_planned_rotation_pre_source_with_before_mutation_gate(gate.clone())
            .expect("admitted ABA rollback");
        gate.wait_until_reached();
        fs::rename(&reservation, &retained).expect("retain original reservation inode");
        fs::create_dir(&reservation).expect("replacement reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))
            .expect("replacement reservation mode");
        for entry in &original.entries {
            owner_file(
                &reservation.join(&entry.name),
                entry.bytes.as_deref().expect("known planned file"),
            );
        }
        gate.resume();
        assert!(run.await.is_err());
        let replacement = reservation_snapshot(&reservation);
        let retained_original = reservation_snapshot(&retained);
        assert_eq!(retained_original, original);
        assert_eq!(replacement.mode, 0o700);
        assert_eq!(replacement.entries.len(), original.entries.len());
        for original_entry in &original.entries {
            let replacement_entry = replacement
                .entries
                .iter()
                .find(|entry| entry.name == original_entry.name)
                .expect("replacement evidence");
            assert_eq!(replacement_entry.bytes, original_entry.bytes);
            assert_eq!(replacement_entry.mode, original_entry.mode);
        }
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
        actor.shutdown().await.expect("joined ABA actor");
    }

    #[tokio::test]
    async fn planned_rotation_debug_and_errors_redact_key_and_transition_identifiers() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let (actor, _stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        let current = current_active_keyring(&root);
        let current_kid = current.active_kid().as_str().to_owned();
        let preparation = planned_rotation_preparation(&root);
        let debug = format!(
            "{preparation:?} {:?} {:?} {:?}",
            current.active_kid(),
            AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                )
            ),
            AuthPlannedRotationRollbackOutcome::NotRollbackable(
                AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                )
            )
        );
        assert!(!debug.contains(&current_kid));
        assert!(!debug.contains("55555555-5555-4555-8555-555555555555"));
        assert!(!debug.contains("66666666-6666-4666-8666-666666666666"));
        assert!(debug.contains("[REDACTED]"));
        actor.shutdown().await.expect("joined redaction actor");
    }

    #[tokio::test]
    async fn dropped_planned_preparation_receiver_does_not_cancel_work_or_release_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let reservation = root
            .join(SECRET_DIRECTORY_NAME)
            .join(".auth-transition-planned-55555555-5555-4555-8555-555555555555");
        let (actor, stores) = actor_and_stores(&root).await;
        advance_initialization_to_clean_active(&actor).await;
        let gate = ActorTestGate::new();
        let run = actor
            .start_prepare_planned_rotation_with_pre_mutation_gate(
                planned_rotation_preparation(&root),
                gate.clone(),
            )
            .expect("admitted dropped planned preparation");
        gate.wait_until_reached();
        drop(run);
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        gate.resume();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !reservation.join("prepared").exists() {
            assert!(
                Instant::now() < deadline,
                "dropped planned preparation did not complete"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            actor
                .inspect_planned_rotation_reconciliation()
                .await
                .expect("planned preparation completed after receiver drop"),
            AuthPlannedRotationReconciliation::PlannedPreSource {
                phase: AuthPlannedRotationPreSourcePhase::Prepared,
                recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
            }
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout after command")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        assert!(stores.conversation.report().await.is_ok());
        actor
            .shutdown()
            .await
            .expect("joined dropped-receiver actor");
        wait_until_lock_available(&root);
    }

    fn wait_until_lock_available(root: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match AuthInstanceLayout::open_or_create(root).and_then(AuthInstanceLayout::lock) {
                Ok(locked) => {
                    drop(locked);
                    return;
                }
                Err(SecretFsError::AlreadyLocked) => {
                    assert!(
                        Instant::now() < deadline,
                        "actor did not release lock after command completion"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("unexpected lock error: {error}"),
            }
        }
    }
}
