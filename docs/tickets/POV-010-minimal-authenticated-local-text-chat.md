# POV-010 Minimal Authenticated Local Text Chat

Status: Completed — 2026-07-31; core/API/Web delivery and pinned repository validation complete

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-007, POV-008

Runtime target: same-origin local production runtime; MacBook macOS dogfood activation evidence is
deferred to POV-038

Development target: Windows frontend and cross-platform repository validation; no production auth
stub or bypass

## Why

model integration 전에 사용자가 실제 local product surface에서 로그인하고 기록을 durable하게 남길 수 있어야 합니다. 저장 실패를 성공처럼 보이는 UI는 제품 신뢰를 훼손합니다.

## What

POV-001의 offline shell에 login, owner-scoped conversation 선택, text submit, durable receipt와 stored timeline을 제공하는 최소 Web Chat을 추가합니다. 생성형 답변 없이 capture 자체를 검증합니다.

## Scope

- local login and logout surface
- same-origin refresh and expired-access recovery
- conversation creation/selection and text composer
- idempotent submit and durable receipt
- stored user-event timeline and error state
- keyboard accessibility and basic status semantics
- no-external-asset offline flow

## HTTP Contract

- `GET /api/conversations`는 verified access session의 owner에게만 conversation ID와 current
  revision 목록을 반환합니다.
- `GET /api/conversations/{conversation_id}`는 같은 owner의 stored event timeline을
  revision 오름차순으로 반환합니다.
- `POST /api/conversations/{conversation_id}/events`는 UUID v4 idempotency key, absent/exact
  expected revision과 exact text content를 받아 existing POV-008 repository에 append합니다.
- request path/body의 owner 값은 받지 않으며 `AuthRuntime::verify_access`가 만든
  `VerifiedAuthContext`만 repository에 전달합니다.
- 첫 append의 absent expected revision은 conversation을 생성하고, 후속 append는 server
  readback의 exact current revision을 사용합니다.
- success response는 commit 뒤 authoritative event/timeline readback이 끝난 뒤에만
  반환합니다.

## Platform Evidence Boundary

- Windows에서 frontend와 Rust repository baseline, model-independent component/contract test를
  실행합니다.
- supported-Unix auth/listener behavior는 기존 production smoke와 WSL-native supplemental
  evidence를 사용하되 macOS 검증으로 확장하지 않습니다.
- MacBook production `auth init`, listener-ready startup, installed-browser
  login/refresh/logout, text capture/readback과 cookie/storage/cache evidence는
  [POV-038](POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md) backlog가
  소유하며 이 ticket의 implementation completion을 막지 않습니다.

## Out Of Scope

- polished design system
- LLM answer, tool call 또는 markdown rendering
- audio/file upload
- PWA install and remote ingress
- Discord adapter

## Acceptance Criteria

- 사용자는 `127.0.0.1:8080` same-origin에서 로그인하고 text event를 저장할 수 있습니다.
- network retry나 submit 재시도가 같은 event를 중복 생성하지 않습니다.
- server readback이 완료되기 전에는 UI가 durable success를 표시하지 않습니다.
- auth expiry, validation, conflict와 storage failure가 서로 구분된 안전한 상태로 보입니다.
- 인터넷을 끊어도 shell, login과 stored text capture에 필요한 외부 asset 요청이 없습니다.
- keyboard만으로 login, submit과 stored event 확인이 가능합니다.
- access/refresh token이 URL, Web Storage, IndexedDB, browser-visible log와 error surface에
  나타나지 않습니다.
- refresh cookie는 exact local profile의 `Path=/api/auth`, `HttpOnly`,
  `SameSite=Strict`와 cache-control contract를 유지하고 logout 뒤 clear됩니다.
- 실제 installed-browser/macOS production 지원은 POV-038 evidence 전까지 주장하지
  않습니다.

## Verification

- component/unit tests using synthetic content
- local auth/conversation HTTP contract와 supported-Unix production smoke
- duplicate submit, auth expiry, storage failure와 token non-persistence component tests
- build asset의 external runtime dependency inspection
- actual repository validation commands and `git diff --check`

## Completion Evidence — 2026-07-31

- `pov-core`는 verified owner별 conversation 목록과 revision 순서 timeline read를
  제공하고 cross-owner read를 `NotFound`로 닫습니다.
- supported-Unix `pov-api`는 `AuthRuntime::verify_access` 뒤에만 세 conversation route를
  열고 path/body에서 owner authority를 받지 않습니다.
- React client는 boot refresh, login/logout, 401 refresh-once retry, conversation
  selection/creation과 authoritative append readback을 제공합니다. Access token은 React
  memory에만 있고 Web Storage API를 사용하지 않습니다.
- Windows에서 repository 조회 표적 테스트, strict append payload 계약 테스트와
  jsdom component test 3건이 PASS했습니다. Component test는 login fallback/token
  non-persistence, 첫 append의 absent revision/401 retry/authoritative render와
  미확인 logout을 성공으로 표시하지 않는 경계를 확인합니다.
- Windows host의 Linux target 교차 check는 bundled SQLite C source용
  `x86_64-linux-gnu-gcc` 부재로 중단됐지만, WSL Ubuntu의 별도 `/tmp` target에서
  `cargo check --locked --workspace --all-targets`와 `cargo test --locked -p pov-api`가
  PASS했습니다. 이는 Unix compile/test evidence이며 macOS production evidence로
  확장하지 않습니다.
- 같은 WSL native `/tmp` 경계에서 production binary build,
  `scripts/test_operator_pty.py`, `scripts/test_production_auth_smoke.py`와
  `KDF_TEST_SERIAL=1 cargo test --locked --workspace --all-targets -- --test-threads=1`이
  PASS했습니다.
- Windows에서 Rust fmt/check/workspace test(153 tests)가 PASS했습니다. Frontend
  format/lint/test/typecheck/build는 Node `22.17.0`/npm `10.9.2`에서 PASS했습니다.
- 정본 Node `26.4.0`/npm `11.17.0`에서 `npm --prefix web ci`,
  format/lint/test/typecheck/build가 모두 PASS했습니다. Vitest test는
  `/// <reference types="vitest/jsdom" />`와 실제 `jsdom.window` Web Storage를 사용해 Node
  26의 file-less global Web Storage와 분리하며 추가 `NODE_OPTIONS` 없이 3건이 PASS합니다.
- Windows Rust 표적 payload contract test, fmt, locked workspace check와 153 tests가
  PASS했습니다. 기존 WSL-native supported-Unix production/auth evidence도 보존합니다.
- 연결 가능한 browser와 target MacBook이 없어 실제 UI/macOS inspection은
  `UNAVAILABLE`이었으며, device-bound production/browser evidence는 POV-038 backlog가
  소유합니다. 이는 POV-010 implementation delivery의 완료를 막지 않으며 macOS
  production 지원 근거로 확장하지 않습니다.

## Rollback

text composer route를 비활성화해도 이미 저장된 conversation event는 source DB에 남고 API로 읽을 수 있어야 합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Roadmap](../WBS.md)
- [POV-001](../deps/POV-001-local-offline-walking-skeleton.md)
- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-008](../deps/POV-008-idempotent-conversation-append-and-outbox.md)
- [POV-038](POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md)
- [ADR-0006](../decisions/0006-h1-development-and-dogfood-platform.md)
