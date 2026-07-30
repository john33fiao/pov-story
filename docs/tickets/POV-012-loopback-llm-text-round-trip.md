# POV-012 Loopback LLM Text Round Trip

Status: Planned

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

- fake-provider round-trip tests
- loopback binding and direct-access negative check
- crash, timeout, cancel, restart and duplicate retry tests
- offline local Web Chat smoke
- actual repository validation commands and `git diff --check`

## Rollback

generation capability를 비활성화해도 login, text capture, timeline과 durable job status는 계속 동작해야 합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-006](../deps/POV-006-provider-ports-and-safe-process-supervisor.md)
- [POV-009](../deps/POV-009-durable-single-slot-job-queue.md)
- [POV-010](POV-010-minimal-authenticated-local-text-chat.md)
