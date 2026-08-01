# POV-038 macOS Dogfood Runtime And Installed-Browser Evidence

Status: In Progress — target available; manual evidence pending

Type: Platform activation evidence

Roadmap: H1 dogfood follow-up — not a POV-010 implementation delivery gate

Depends on: POV-007, POV-010, POV-040, target MacBook access

## Why

H1의 intended always-on backend는 MacBook의 macOS입니다. 장비가 없던 동안 production
auth와 installed-browser 검증을 POV-010의 완료 차단 조건으로 두지 않았고, 현재 확보한
target 장비에서 별도 evidence slice로 실행합니다.

## Activation Boundary

- 2026-08-01 현재 target MacBook을 사용할 수 있어 `Ready`로 전환했습니다.
- 실행 전 POV-007/010의 current code, accepted ADR과 documented commands를 다시 읽습니다.
- 이 ticket이 완료되기 전에는 macOS production/dogfood 또는 installed-browser 지원을
  완료로 주장하지 않습니다.
- 실행 조합은 macOS `26.5.2` (`25F84`, arm64)와 Google Chrome `150.0.7871.187`로
  제한합니다. Password, recovery code, token, cookie value, KID, instance/model path와
  artifact hash는 evidence에 기록하지 않습니다.
- POV-013 fail-fast로 credential-bearing manual flow는 아직 실행하지 않았습니다.
  [POV-040](POV-040-reconcile-macos-raw-filename-validation.md)의 target-macOS full baseline은
  2026-08-01 완료됐으며, 이 ticket의 production/browser evidence가 다음 미실행 경계입니다.

## Scope

- owner-only instance root와 controlling-TTY production `auth init`
- listener-ready startup과 second-init no-replace
- macOS loopback same-origin `127.0.0.1:8080` installed-browser flow
- login, refresh-once recovery, logout/revoke와 text capture/readback
- refresh cookie flag/clear, URL, Web Storage, IndexedDB, cache와 offline asset inspection
- synthetic text만 사용하는 redacted evidence와 exact browser/macOS version 기록

## Acceptance Criteria

- production `auth init`가 redirect할 수 없는 controlling TTY와 owner-only root에서
  성공하고 secret, password와 recovery code를 evidence에 노출하지 않습니다.
- initialized runtime이 listener-ready가 되고 second init이 기존 owner/key material을
  교체하지 않습니다.
- installed browser에서 login, access expiry 뒤 refresh, idempotent text submit,
  authoritative timeline readback과 logout/revoke가 동작합니다.
- access/refresh token이 URL, Web Storage, IndexedDB, browser-visible log 또는 error
  surface에 나타나지 않습니다.
- refresh cookie가 exact local profile을 유지하고 logout 뒤 clear되며 API/auth/personal
  data가 cache되지 않습니다.
- 외부 asset 요청 없이 shell과 stored text capture가 동작합니다.
- 실행한 MacBook model, macOS와 browser/version만 PASS로 기록하고 다른 조합으로
  확장하지 않습니다.

## Verification

- README의 pinned frontend/Rust baseline
- Linux 전용 `python scripts/test_operator_pty.py`와
  `python scripts/test_production_auth_smoke.py`는 macOS PASS 근거에서 제외
- initialized owner-only instance의 `POV_INSTANCE_ROOT=/absolute/private/path sh scripts/smoke.sh`
- installed-browser login/refresh/logout, duplicate submit, auth expiry와 durable readback
- browser network/cookie/storage/cache inspection과 redacted evidence readback
- `git diff --check`와 relative Markdown-link check

## Out Of Scope

- native Windows production auth
- LAN exposure, remote ingress 또는 MacBook backend를 Windows에서 직접 사용하는 개발 우회
- new auth bypass, weaker cookie profile 또는 synthetic production owner authority
- Safari/Chrome 등 실행하지 않은 browser 조합의 지원 claim

## Rollback

실기 검증이 실패하면 platform claim을 열지 않고 이 ticket을 `In Progress`로 유지합니다.
POV-010의 이미 검증된 implementation delivery를 되돌리거나 macOS 실패를 Windows 성공으로
대체하지 않습니다.

## Links

- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-010](POV-010-minimal-authenticated-local-text-chat.md)
- [POV-040](POV-040-reconcile-macos-raw-filename-validation.md)
- [ADR-0006](../decisions/0006-h1-development-and-dogfood-platform.md)
- [Architecture](../ARCHITECTURE.md)
- [TODO](../TODO.md)
- [WBS](../WBS.md)
