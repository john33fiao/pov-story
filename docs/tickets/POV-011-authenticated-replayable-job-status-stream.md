# POV-011 Authenticated Replayable Job Status Stream

Status: In Progress

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-009, POV-010

## Why

긴 local 작업은 page refresh, token expiry와 연결 중단 뒤에도 상태를 잃지 않아야 합니다. query-string token이나 cache된 status로 이를 해결하면 개인정보 경계가 약해집니다.

## What

Bearer access token을 사용하는 fetch-streaming SSE와 durable status cursor를 구현합니다. client는 access token 만료 전에 stream을 닫고 refresh 뒤 마지막 cursor부터 owner-scoped 상태를 재개합니다.

## Scope

- durable job status event and monotonically ordered cursor
- Authorization header 기반 fetch streaming
- reconnect, resume and duplicate suppression
- token refresh handoff
- owner scope, cache-control and redaction
- bounded heartbeat and disconnect cleanup

## Out Of Scope

- native EventSource query token
- WebSocket
- push notification
- Cloudflare deployment tuning
- multi-device fanout

## Acceptance Criteria

- status stream URL, query, browser storage와 log에 access/refresh token이 남지 않습니다.
- 다른 owner의 job status와 cursor를 읽을 수 없습니다.
- access token 만료 전에 stream이 종료되고 refresh 뒤 마지막 durable cursor에서 재개됩니다.
- reconnect 뒤 terminal/progress event가 유실되거나 사용자에게 중복 적용되지 않습니다.
- API, SSE와 auth response가 browser/service-worker/proxy cache 대상이 아닙니다.
- client disconnect와 server cancel 뒤 stream task나 resource가 누수되지 않습니다.

## Verification

- owner isolation and invalid cursor tests
- expiry/refresh/reconnect browser test
- duplicate, gap and terminal event replay tests
- cache header and token leakage inspection
- actual repository validation commands and `git diff --check`

## Implementation Evidence — 2026-07-31

구현된 current-tree 범위:

- immutable migration `0003`의 global `event_sequence`를 재사용하는 canonical decimal
  `JobEventCursor`, owner-scoped 128-event page와 cross-owner/missing cursor fail-closed read
- bearer-only `GET /api/jobs/events?after=<cursor>` JSON polling과 no-query
  `GET /api/jobs/events/stream` fetch-streaming SSE
- 동일 content-free payload serializer, 500ms poll, 10초 heartbeat, 최대 15초 active-session
  재검증과 별도 task 없는 drop-cancellable stream
- zeroizing retained bearer, sessionStorage cursor-only resume, 5초 전 single-flight refresh,
  duplicate suppression, bounded reconnect와 strict polling fallback
- `@playwright/test` `1.62.1` Chromium synthetic-stream evidence와 passive connection status

PASS:

- Node `26.4.0`, npm `11.17.0`에서 frontend format/lint, Vitest 10건, typecheck와 production
  build
- Playwright `1.62.1` Chromium 1건: expiry refresh handoff, reload resume, exact
  URL/Authorization/credentials/cache, Web Storage와 Cache API token canary 부재
- `cargo fmt --all -- --check`, `git diff --check`
- `/private/tmp` diagnostic copy에서 기존 macOS `Termios.line_discipline` 비교 한 줄만
  제거한 뒤 locked workspace check와 serial full suite PASS: `pov-core` 313 PASS/1 ignored,
  process-supervisor 22 PASS/15 ignored, 나머지 API/contract suite PASS. 이 결과는 POV-011
  변경 compile/test 격리를 위한 진단이며 실제 repository supported-Unix PASS가 아닙니다.
- actual macOS 26.5.2 arm64, Rust/Cargo 1.95.0의 current tree에서 `rustix 1.1.4`가
  제공하는 공통 `Termios` 필드와 속도는 그대로 비교하고 Linux에서만 공개되는
  `line_discipline` 비교를 해당 target으로 제한했습니다.
  `cargo check --locked -p pov-core --all-targets`, operator 단위 테스트 3건, production CLI
  테스트 2건, `cargo fmt --all -- --check`, locked workspace check가 PASS했습니다.
- 같은 current tree의 두 번째 exact `cargo test --locked --workspace --all-targets`가
  PASS했습니다: `pov-core` 313 PASS/1 ignored, process-supervisor 22 PASS/15 ignored, 나머지
  API/contract suite PASS. Frontend format/lint/typecheck/production build도 PASS했습니다.

OBSERVED NON-REPRODUCED FAILURE:

- 첫 번째 exact full workspace test는
  `planned_rotation_preparation_durability_faults_have_exact_fresh_actor_phases`가 macOS APFS
  identity 재검증 중 `IdentityChanged`로 1회 FAIL했습니다. 동일 test의 즉시 exact 직렬
  재실행과 이후 exact full workspace 재실행은 PASS해 root cause가 재현되지 않았습니다.
  이 관측을 `Termios` 수정의 성공으로 숨기거나 해당 auth maintenance 경계를 수정하지
  않습니다.

REMAINING / UNAVAILABLE:

- 이 수정 뒤 supported Linux/WSL-native tree에서 locked workspace check, KDF-serialized
  test, production binary build, `scripts/test_operator_pty.py`와
  `scripts/test_production_auth_smoke.py`를 아직 실행하지 않았습니다.
- 현재 macOS에서 `scripts/test_operator_pty.py`와
  `scripts/test_production_auth_smoke.py`는 Linux-only로 UNAVAILABLE이고, production
  `auth init`을 완료한 private instance가 없어 `scripts/smoke.sh`도 실행하지 않았습니다.

따라서 macOS compile/test baseline은 복구됐지만 구현을 completion evidence로 승격하지
않습니다. 실제 supported Linux tree에서 locked check/test 및 auth/PTY/production smoke를
PASS하고 RTD After를 반복할 때만 `Completed`로 전환합니다.

## Rollback

stream endpoint를 끄고 durable status를 polling으로 읽는 임시 fallback을 사용할 수 있어야 합니다. status event와 cursor history는 보존합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-009](../deps/POV-009-durable-single-slot-job-queue.md)
- [POV-010](POV-010-minimal-authenticated-local-text-chat.md)
