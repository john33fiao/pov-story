# POV-008 Idempotent Conversation Append And Outbox

Status: Completed — 2026-07-29; persistence acceptance, production auth dependency and final validation verified

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-004, POV-007

## Why

사용자 입력은 모델이나 derivative 처리보다 먼저 durable source event로 남아야 합니다. network retry나 embedding failure가 같은 입력을 중복 저장하거나 원문을 잃게 해서는 안 됩니다.

## What

owner-scoped conversation, append-only event, idempotency key, audit와 transactional outbox의 최소 vertical slice를 구현합니다. commit 뒤 같은 source를 다시 읽어 postcondition을 확인합니다.

## Scope

- conversation identity와 user event append
- owner-scoped idempotency key와 request fingerprint
- source event와 outbox의 same-store transaction
- post-commit readback과 correlation ID
- assistant/tool event를 추가할 확장 contract
- synthetic retry, conflict와 failure fixture

## Out Of Scope

- LLM generation
- job dispatcher와 streaming status
- Knowledge 또는 Calendar mutation
- embedding consumer 구현
- audio/media event

## Acceptance Criteria

- 같은 owner, idempotency key와 fingerprint의 retry는 하나의 source event만 반환합니다.
- 같은 key에 다른 payload가 오면 기존 event를 변경하지 않고 conflict를 반환합니다.
- source event와 outbox는 같은 Conversation transaction에서 commit됩니다.
- embedding consumer가 offline이거나 실패해도 source append가 유지됩니다.
- commit 뒤 readback이 owner, event ID, content hash와 correlation ID를 검증합니다.
- 다른 owner는 conversation, event, idempotency result와 outbox payload를 조회할 수 없습니다.

## Verification

- repository contract and migration tests
- concurrent/replayed append and fingerprint conflict tests
- outbox failure independence and post-commit readback tests
- actual repository validation commands and `git diff --check`

## Implemented Core Evidence — 2026-07-25

- append-only Conversation migration `0002` preserves applied `0001` and adds owner-composite conversation, event, idempotency, outbox and audit constraints.
- typed repository accepts only opaque `VerifiedAuthContext`, UUID v4 target/key and exact UTF-8 content of 1~64KiB; caller-supplied owner, digest and correlation are not part of the command.
- request fingerprint covers a versioned domain, owner, target, absent/exact expected revision, user-event kind and length-delimited exact content bytes.
- `BEGIN IMMEDIATE` performs idempotency lookup before revision validation, then conversation CAS, event, outbox, audit and idempotency insert in one source transaction.
- post-commit joined readback recomputes the content hash and verifies fingerprint, correlation and the event/outbox/audit relationship before returning success.
- synthetic tests cover independent-connection same-key and same-revision races, a later revision committed between commit/readback, payload/target/revision conflicts, cross-owner fail-closed reads, exact-byte roundtrip, UPDATE/DELETE/REPLACE immutable triggers, pre-outbox rollback, response-loss recovery, queued report/backup poison recheck, dirty-writer reopen, backup/reopen and redacted Debug output.

## Completion Evidence

- [x] POV-007 provides the production issuer/verifier for `VerifiedAuthContext`.
  `AuthRuntime::verify_access` validates the local JWT, active session, credential version,
  enabled account and active key lifecycle before minting the owner capability. The synthetic
  constructor remains test-only and this ticket adds no listener bypass or raw production
  constructor.
- [x] 2026-07-29 close-out audit rechecked the migration, repository and targeted tests against
  every acceptance criterion. `pov-api` activation and authenticated browser flow remain
  [POV-010](POV-010-minimal-authenticated-local-text-chat.md) scope and are not claimed here.
- [x] Final changed-set repository validation passes: frontend format/lint/typecheck/build,
  Rust format/workspace check/workspace test, Markdown relative links and `git diff --check`.
- [x] Project-local RTD After completed all 13 review/readiness steps as READY on the final changed
  set. The repository's intentionally ignored local `AGENTS.md` and RTD Before/After skills were
  restored from current code, manifest and canonical-document facts before this gate ran.

## Rollback

신규 append endpoint를 닫되 이미 기록된 source event와 outbox를 삭제하지 않습니다. schema rollback은 data-preserving forward migration으로만 수행합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-004](../deps/POV-004-core-data-identity-and-store-boundaries.md)
- [POV-007](POV-007-local-login-refresh-and-session-revoke.md)
