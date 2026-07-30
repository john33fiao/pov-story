# POV-005 Authentication And Session Security Decision

Status: Completed

Completed: 2026-07-25

Type: Decision

Roadmap: H0 — Reproducible local boundary

Depends on: POV-001

## Why

JWT signing, key lifecycle, refresh lifetime와 local browser cookie 경계가 미결정인 상태에서 auth code를 만들면 owner isolation과 recovery contract가 구현마다 달라집니다. 개인 데이터를 저장하기 전에 threat와 test 기준을 결정해야 합니다.

## What

local과 remote profile의 ID/password session, access token, opaque refresh rotation, replay revoke, cookie, CSRF, key rotation과 account recovery 경계를 ADR과 executable test matrix로 확정합니다.

## User Outcome

후속 인증 구현이 owner scope, password/session/recovery와 signing-key crash state를 추정하지 않고 하나의 fail-closed 계약과 ticket별 executable evidence 범위에서 진행됩니다. 사용자는 local login·logout·recovery가 DB failure나 browser profile 차이에도 성공한 것처럼 보이지 않는 경계를 먼저 확보합니다.

## Scope

- signing algorithm allowlist와 key generation, storage, rotation, rollback
- access 및 refresh idle/absolute lifetime
- refresh rotation, replay detection, logout와 forced revoke
- local loopback HTTP와 remote HTTPS cookie/session profile
- password storage, login rate limit와 recovery boundary
- token redaction, browser storage와 SSE/upload refresh test matrix

## Out Of Scope

- auth endpoint와 UI 구현
- production secret 또는 real account 생성
- TOTP implementation
- Cloudflare deployment
- shared workspace authorization

## Acceptance Criteria

- accepted ADR이 algorithm, key lifecycle, token lifetime, refresh replay, revoke와 recovery를 모호하지 않게 결정합니다.
- `owner_id`는 검증된 token subject와 active session에서만 결정됩니다.
- local loopback browser compatibility와 remote cookie flag 차이를 재현 가능한 방법으로 검증합니다.
- token이 URL, Web Storage, IndexedDB, application/proxy/audit log에 남지 않는 test case가 정의됩니다.
- password change, user disable, logout와 refresh replay 이후 session behavior가 정의됩니다.
- unresolved residual risk와 decision rollback/supersede 절차가 기록됩니다.

## Definition Of Done

- Accepted ADR이 clean bootstrap과 key loss를 구분하고 password, JWT, key lifecycle, session/refresh, recovery, cookie/CSRF, secret ingress, redaction/cache와 commit-before-response 경계를 exact contract로 결정합니다.
- Executable test matrix가 POV-007 local/auth-API, POV-011 SSE, POV-015 upload와 future trusted HTTPS remote-auth delivery의 clause ownership을 구분합니다.
- Synthetic cookie probe와 recorded browser evidence가 local cookie acceptance, same-host cross-port leakage와 local/remote header 차이를 실제 account/token 없이 재현합니다.
- Auth schema, endpoint, issuer/verifier 또는 installed-browser production flow를 구현·검증한 것으로 보고하지 않습니다.
- README, Architecture, Open Questions, TODO, WBS, dependency index와 POV-007가 accepted decision 및 completed status와 일치합니다.
- 아래 실제 validation과 갱신된 project-local RTD After가 모두 통과한 뒤 completed archive로 이동합니다.

## Verification

- ADR review against Architecture identity boundary
- threat and abuse-case walkthrough
- browser compatibility check plan using synthetic account data
- `npm --prefix web run format:check`
- `npm --prefix web run lint`
- `npm --prefix web run typecheck`
- `npm --prefix web run build`
- `node --check scripts/auth-cookie-probe.mjs`
- `node scripts/auth-cookie-probe.mjs` local/header conditional probe
- `cargo fmt --all -- --check`
- `cargo check --locked --workspace --all-targets`
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `cargo test --locked --workspace --all-targets`
- `cargo build --locked --workspace --release`
- `sh scripts/smoke.sh`
- changed Markdown relative-link check
- `git diff --check`

## Completion Evidence

- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)가 EdDSA/Ed25519 JWT, Argon2id password, clean-instance sentinel과 resumable signing-key initialization/lifecycle, local/remote cookie, refresh lifetime·rotation·replay, revoke, recovery와 owner-context issuer 경계를 exact contract로 accepted했습니다.
- threat/abuse walkthrough는 first-run/key-loss confusion, dirty-writer commit uncertainty와 initialization crash, identifier/algorithm confusion, account/session mismatch, verifier-to-commit race, refresh replay·response loss·bounded generation, CSRF/DNS rebinding, local cookie port leakage, storage/log/cache, SSE와 upload expiry/revoke를 executable test ID로 연결했습니다.
- `scripts/auth-cookie-probe.mjs`의 dedicated `localhost` Host/probe-name synthetic HttpOnly canary를 Chrome/150.0.0.0 user-agent를 보고한 Codex in-app Chromium engine에서 실행했습니다. Primary와 다른 `localhost` port가 모두 cookie를 받고 clear 뒤 secondary가 `false`가 됐습니다. 이는 해당 engine의 local acceptance와 local HTTP port 비격리를 production `127.0.0.1` cookie 간섭 없이 보여주는 evidence입니다.
- `curl`로 production cookie를 issue하지 않는 local/remote `X-POV-Set-Cookie-Specimen` 차이를 확인하고 installed browser 재검증, trusted HTTPS conditional test와 unsupported browser 처리 방법을 ADR에 기록했습니다. Browser probe는 dedicated name만 issue/clear해 future real refresh cookie와 간섭하지 않습니다. 실제 installed Chrome/Safari local auth flow는 POV-007의 release gate이고 remote profile은 trusted ingress evidence 전 비활성입니다.
- raw token, password, recovery code, account 또는 개인 데이터는 만들거나 저장소에 기록하지 않았습니다.
- residual risk는 local cookie의 port 비격리, XSS/bearer replay와 forced refresh-generation exhaustion, strict refresh race UX, fixed one-hour login-admission/outcome uncertainty와 bounded session orphan, Argon2 availability, saved-code loss lockout, key backup과 remote ingress evidence로 구분했습니다.
- 실제 repository validation과 갱신된 13-step project-local RTD After가 통과했으며 auth implementation과 installed Chrome/Safari/trusted HTTPS evidence는 후속 gate로 남겼습니다.

## Rollback

구현 전에는 ADR을 supersede해 결정을 바꿀 수 있습니다. auth 구현 뒤에는 token/session migration과 forced revoke 영향을 평가하는 새 ADR 없이 계약을 되돌리지 않습니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Open Questions](../OPEN_QUESTIONS.md)
- [Roadmap](../WBS.md)
- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)
- [POV-001](../deps/POV-001-local-offline-walking-skeleton.md)
- [POV-007](POV-007-local-login-refresh-and-session-revoke.md)
