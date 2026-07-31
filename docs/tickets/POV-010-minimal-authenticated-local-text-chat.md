# POV-010 Minimal Authenticated Local Text Chat

Status: Ready — ADR-0006 macOS runtime target and Windows development role accepted

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-007, POV-008

Runtime target: MacBook macOS same-origin production runtime

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
- installed-browser cookie, URL, storage, cache와 redaction evidence

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
- MacBook macOS에서 production `auth init`, listener-ready startup, installed-browser
  login/refresh/logout, text capture/readback과 cookie/storage/cache evidence를 실행합니다.
- macOS 실기 evidence를 실행하기 전에는 구현이 끝나도 이 ticket을 `Completed`로 바꾸지
  않습니다.

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
- evidence를 실행한 installed browser/version만 PASS로 기록하며 unavailable Chrome/Safari
  조합을 검증된 것으로 확장하지 않습니다.

## Verification

- component/unit tests using synthetic content
- local same-origin capture smoke
- duplicate submit, auth expiry and storage failure browser test
- offline browser network inspection
- installed-browser login/refresh/logout, cookie flags, URL/storage/cache inspection
- actual repository validation commands and `git diff --check`

## Rollback

text composer route를 비활성화해도 이미 저장된 conversation event는 source DB에 남고 API로 읽을 수 있어야 합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Roadmap](../WBS.md)
- [POV-001](../deps/POV-001-local-offline-walking-skeleton.md)
- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-008](../deps/POV-008-idempotent-conversation-append-and-outbox.md)
- [ADR-0006](../decisions/0006-h1-development-and-dogfood-platform.md)
