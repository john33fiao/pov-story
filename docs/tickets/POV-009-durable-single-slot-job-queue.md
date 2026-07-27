# POV-009 Durable Single-slot Job Queue

Status: In Progress — durable persistence core implemented; runtime activation pending

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-008

## Why

local model과 media process가 제한된 장치 자원을 다투면 기록 처리와 상태가 예측 불가능해집니다. 긴 작업은 crash와 restart 뒤에도 하나의 durable job으로 복구되어야 합니다.

## What

Conversation DB에 job state, attempt, fenced lease, fixed-normal FIFO, retry schedule, timing과 content-free durable event history를 구현합니다. internal global sequence는 POV-011 replay cursor용으로 예약했지만 cursor query와 SSE는 아직 없습니다. 현재 dependency-independent persistence core와 typed owner repository/internal dispatcher surface는 구현됐으며, 실제 background dispatcher와 provider 실행은 아직 연결하지 않습니다.

## Current Implementation

- Conversation migration `0003`이 outbox-backed job, enqueue와 owner mutation idempotency ledger, attempt, content-free event와 singleton queue control을 추가합니다.
- owner-facing enqueue/read/cancel/resume는 `VerifiedAuthContext`를 요구하고, internal dispatcher만 claim, running 전환, renew, finish와 recovery resolution을 수행합니다. cancel/resume도 server-validated revision과 typed key/fingerprint를 ledger에 함께 commit해 response loss 뒤 같은 결과를 replay합니다.
- enqueue는 immutable POV-008 outbox pointer를 source로 사용하며 payload를 job table에 복제하지 않습니다. 같은 key/fingerprint는 기존 receipt를 replay하고 다른 request 또는 같은 `(owner, outbox, kind)` 중복은 거부합니다. key를 잃은 caller는 exact owner/outbox/kind lookup으로 committed job 유무를 복구할 수 있습니다.
- 현재 job kind는 `conversation_response_v1`, priority는 server-owned fixed normal `0`입니다. runnable 선택은 durable enqueue sequence FIFO이며 caller가 priority, timeout, retry policy를 선택하지 않습니다.
- singleton control의 증가 generation과 opaque token이 active attempt를 fence합니다. `leased`는 외부 실행 시작 전, `running`은 시작 뒤 상태이며 queue wait와 execution duration을 분리합니다.
- lease 만료 시각 자체를 expired로 취급합니다. 시작 전 lease expiry는 attempt history를 보존하고 retry budget에 따라 재예약하거나 실패합니다. 시작 뒤 expiry는 이전 실행 부재를 추정하지 않고 job, attempt와 singleton을 `recovery_required`로 보존해 모든 claim을 중단합니다. explicit confirmed-stopped resolution만 retry 또는 terminal state로 해제합니다.
- queued/leased/waiting cancellation은 안전하게 terminal 처리하고, running cancellation은 worker가 renew에서 `cancel_requested`를 관찰한 뒤 cleanup acknowledgement를 commit할 때까지 슬롯을 유지합니다. waiting-confirmation은 execution slot을 점유하지 않으며 다음 attempt budget이 남은 경우에만 진입합니다.
- job/attempt/event/retry 상태, queue wait와 execution timing은 reopen 뒤에도 남습니다. enqueue는 same-key replay와 source lookup, cancel/resume은 same-key ledger replay, finish는 같은 held capability/outcome readback으로 response loss를 복구합니다. 유실된 claim capability 자체는 재구성하지 않으며 시작되지 않은 attempt 하나가 lease expiry까지 슬롯을 보수적으로 점유한 뒤 retry 또는 terminal history로 남습니다.
- queue clock은 DB의 마지막 관측 wall-clock보다 뒤로 갈 때 mutation 없이 fail closed하고, 시간이 그 floor를 따라잡으면 다시 진행합니다. 운영자 reset 계약은 없습니다.
- global event sequence는 POV-011 cursor를, job별 비공개 result-append idempotency key는 POV-012의 assistant append를 위해 예약합니다. 현재 owner-facing read model에는 두 capability를 노출하지 않습니다.

## Scope

- job state machine과 허용 transition
- durable enqueue와 cancel/resume mutation idempotency 및 source lookup
- global execution lease 1개와 same-priority FIFO
- attempt, timeout, cancellation과 retry metadata
- queue wait와 execution duration 분리
- expired lease recovery와 audit event

## Out Of Scope

- multi-worker placement
- per-user concurrency 또는 priority policy 확장
- 실제 LLM/STT execution
- background dispatcher loop와 process/provider wiring
- production auth issuer와 HTTP/API activation
- SSE transport
- WAITING_CONFIRMATION UX

## Acceptance Criteria

- 동시에 execution slot을 점유한 job은 시스템 전체에서 하나를 넘지 않습니다.
- 같은 priority의 runnable job은 durable enqueue order로 lease를 얻습니다.
- 동일 enqueue retry는 job을 중복 생성하지 않습니다.
- expired lease는 이전 attempt를 보존하며 안전한 새 attempt 또는 terminal failure로 전환됩니다.
- confirmation처럼 사용자 입력을 기다리는 상태는 execution slot을 점유하지 않습니다.
- queue wait와 execution timing이 별도 field와 event로 기록됩니다.
- 마지막 attempt는 confirmation 대기로 전이하지 않고 follower FIFO를 막지 않습니다.
- persisted wall-clock이 뒤로 가면 queue admission/mutation은 mutation 없이 fail closed합니다.

현재 persistence core는 이 criteria를 겨냥한 synthetic repository target을 갖지만, ticket은 runtime end-to-end acceptance 전까지 완료하지 않습니다.

## State And Recovery Boundary

```text
queued | retry_scheduled
  -> leased -> running
  -> cancelled

running
  -> succeeded | retry_scheduled | waiting_confirmation | failed
  -> cancel_requested -> cancelled
  -> recovery_required

waiting_confirmation
  -> queued | cancelled

recovery_required
  -> retry_scheduled | failed | cancelled
```

`leased`, `running`, `cancel_requested`, `recovery_required`는 singleton active capability와 결합됩니다. `recovery_required`는 terminal 성공이 아니라 system-wide halt이며, expired started work의 부재를 외부에서 확인하기 전에는 새 attempt를 만들지 않습니다.

## Verification

현재 test targets:

- enqueue replay/conflict, duplicate source와 cross-owner fail-closed
- independent store handle의 concurrent singleton claim과 fixed-normal FIFO
- shared DB를 여는 두 child process의 singleton claim
- exact-boundary expiry, expired unstarted lease retry와 stale capability fencing
- started lease expiry의 `recovery_required` halt와 explicit recovery resolution
- queued/leased/running/waiting cancellation transition과 worker renew의 cancel 관찰
- enqueue source lookup과 cancel/resume mutation의 response-loss replay
- durable retry backoff, max-attempt terminal state와 final-attempt waiting-confirmation 거부
- queue wait/execution timing 분리, reopen persistence와 immutable event history
- enqueue rollback, claim response-loss recovery, job별로 구분되는 result-append key의 retry/reopen 안정성과 Debug redaction
- persisted clock regression의 mutation-free fail-closed 및 floor recovery
- migration exact-prefix, invalid transition, job/enqueue ledger/owner-mutation ledger/attempt/event/singleton control의 UPDATE/DELETE/`INSERT OR REPLACE` guard

최종 evidence 대상으로 workspace fast validation과 `git diff --check`를 사용합니다. 이 문서는 아직 실행 결과나 PASS 수치를 확정하지 않습니다.

## Rollback

dispatcher를 중지하고 queued/running job을 안전한 terminal 또는 pending 상태로 보존할 수 있어야 합니다. job history를 삭제해 rollback하지 않습니다.

## Remaining Activation And Integration

- POV-007의 production auth issuer/verifier가 없어 owner-facing repository를 실제 request에 활성화할 수 없습니다.
- POV-008 append/outbox persistence는 구현됐지만 API와 runtime outbox ingestion이 아직 연결되지 않았습니다.
- POV-010이 authenticated local text intake와 durable receipt를 실제 Web Chat에 연결해야 합니다.
- POV-011이 owner-scoped event history를 authenticated replayable SSE cursor로 노출해야 합니다.
- POV-012가 supervised loopback provider, process-absence 확인과 job completion/result append를 연결해야 합니다.
- POV-013 전체 evidence gate 전에는 H1 delivery 완료를 주장하지 않습니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-008](POV-008-idempotent-conversation-append-and-outbox.md)
