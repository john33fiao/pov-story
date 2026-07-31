# POV-012 Loopback LLM Text Round Trip

Status: Completed — 2026-07-31

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-006, POV-009, POV-010

## Why

첫 local inference는 source event, queue와 ProcessSupervisor 경계를 우회하지 않고 failure를 사용자에게 정직하게 보여야 합니다. model을 붙였다는 사실보다 안전한 왕복이 중요합니다.

## What

stored user event에서 job을 만들고, loopback-only LLM provider를 호출해 assistant event와 provenance를 append하는 최소 text round trip을 구현합니다. model candidate는 benchmark 전 release invariant가 아닙니다.

## Scope

- text generation job and provider request
- long-running loopback server health/start/restart mapping
- assistant event append and input/output provenance
- timeout, cancellation and crash result
- Web Chat receipt, progress and final/error display
- deterministic fake-provider regression path

## Out Of Scope

- autonomous tool use
- memory retrieval 또는 prompt personalization
- model quality gate 확정
- cloud LLM
- parallel generation

## Acceptance Criteria

- inference endpoint는 loopback에서만 수신하고 browser, LAN 또는 Tunnel에 직접 노출되지 않습니다.
- user source event는 model failure와 무관하게 보존됩니다.
- assistant result가 source event, job/attempt, backend, runtime/artifact revision/hash와 elapsed time에 연결됩니다.
- retry가 assistant event나 job을 중복 생성하지 않습니다.
- crash, timeout, cancellation과 unavailable provider가 구분된 job/UI state로 보입니다.
- fake provider로 전체 round trip을 인터넷과 model artifact 없이 검증할 수 있습니다.

## Verification

- deterministic fake-provider가 authenticated round trip, unauthorized `401`, health/model
  identity, restart, port collision, artifact mismatch, crash, timeout, cancel과 confirmed
  process-group absence를 검증합니다.
- Core persistence tests가 migration cursor, disabled-mode skip, scanner recovery, duplicate
  enqueue/result replay, atomic assistant completion, reopen persistence, owner isolation,
  immutable provenance와 `cleanup_uncertain` recovery halt를 검증합니다.
- Web component/SSE tests가 저장 receipt와 generation 상태 분리, reconnect cursor,
  authoritative terminal readback, cancel idempotency, malformed linkage 거부와
  unavailable/timeout/crash/cancel/recovery UX를 검증합니다.
- 현재 macOS의 명시적으로 pin한 Gemma GGUF narrow candidate와 llama.cpp runtime으로 source
  저장부터 authenticated inference, assistant/provenance append, reasoning-off output,
  unauthenticated inference 거부와 clean provider shutdown까지 자동화된 왕복을 통과했습니다.
  이 증거는 release default, 품질 gate 또는 installed-browser production activation이 아닙니다.
- frontend format/lint/typecheck/test/build, Rust format/locked workspace check/test,
  KDF-serialized workspace test, `git diff --check`와 relative Markdown link check를
  completion baseline으로 사용합니다.

## Implementation Evidence

- Conversation migration `0006`은 기존 outbox 최대 sequence에서 generation cursor를
  시작하고 immutable generation result provenance를 추가합니다. 기존 migration은 변경하지
  않았습니다.
- background scanner와 single-slot worker는 요청 경로 enqueue 손실을 복구하고, generation
  disabled 동안 cursor만 전진시켜 나중에 과거 기록을 backfill하지 않습니다.
- provider 성공은 assistant event, provenance, job/attempt 성공을 한 SQLite transaction에
  commit하며 같은 result key replay는 새 assistant event를 만들지 않습니다.
- provider는 canonical absolute artifact와 SHA-256을 실행 직전에 확인하고 exact
  `127.0.0.1`, single slot, 8K context, reasoning/tools/cache off, ephemeral API key로만
  lazy-start합니다. browser와 Axum은 inference port를 route하지 않습니다.
- same-origin timeline/append는 owner-scoped generation summary를 반환하고 SSE는
  conversation/source linkage를 포함합니다. cancellation은 exact job revision과 UUID v4
  idempotency key를 기존 durable queue contract로 처리합니다.

## Rollback

generation capability를 비활성화해도 login, text capture, timeline과 durable job status는 계속 동작해야 합니다.

필수 LLM 환경변수를 모두 제거하면 capture-only disabled mode가 되고, 일부만 있거나 artifact
검증이 실패하면 HTTP와 text capture는 유지한 채 generation job이 `provider_unavailable`로
종료됩니다. Schema rollback은 migration `0006` 적용 전 backup 복원으로만 수행합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-006](../deps/POV-006-provider-ports-and-safe-process-supervisor.md)
- [POV-009](../deps/POV-009-durable-single-slot-job-queue.md)
- [POV-010](POV-010-minimal-authenticated-local-text-chat.md)
