# ADR-0006: H1 Development And Dogfood Platform

- Status: Accepted
- Date: 2026-07-31
- Last amended: 2026-07-31 — device-bound macOS evidence split to POV-038
- Decision owner: repository owner
- Related delivery: [POV-010](../tickets/POV-010-minimal-authenticated-local-text-chat.md),
  [POV-038](../tickets/POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md)

## Context

POV Story의 최종 always-on backend는 MacBook에서 운영할 예정입니다. 동시에 H1을 구현하는
동안 Windows workstation에서 코드 작성, frontend 확인과 cross-platform validation을 계속할
수 있어야 합니다.

현재 production auth maintenance/runtime은 supported Unix에서만 활성화되며 native Windows는
성공 stub 없이 fail closed합니다. Windows production auth를 POV-010의 선행 조건으로 만들면
실제 배포 방향과 무관한 platform delivery가 H1 text capture를 막게 됩니다. 반대로 Windows
개발 편의를 위해 production auth 우회나 synthetic owner authority를 추가하면 인증 경계가
약해집니다.

## Decision

- H1의 intended always-on backend와 dogfood runtime target은 MacBook의 macOS입니다.
- macOS는 existing supported-Unix auth profile을 사용합니다. Production claim에는 MacBook
  실기에서 controlling-TTY `auth init`, owner-only instance root, listener-ready startup,
  second-init no-replace와 installed-browser login/refresh/logout·cookie/storage evidence가
  필요합니다.
- Windows는 H1의 supported development and cross-platform validation environment입니다.
  Rust workspace check/test, frontend format/lint/typecheck/build, 문서와 test-only fixture 작업을
  수행할 수 있지만 production auth maintenance/runtime 지원을 주장하지 않습니다.
- Windows 개발을 위해 listener bypass, production auth stub, raw/synthetic
  `VerifiedAuthContext`, request-body owner authority 또는 weaker cookie profile을 추가하지
  않습니다.
- Native Windows auth delivery ticket은 POV-010의 activation gate가 아닙니다. 향후 Windows
  자체를 production backend로 지원하기로 결정할 때 별도 ticket과 platform evidence를
  먼저 만듭니다.
- WSL은 supplemental Unix validation에 사용할 수 있지만 chosen always-on backend는
  아닙니다. Unix 성공 근거에는 `/mnt/c`가 아닌 WSL-native owner-only path를 사용합니다.
- Windows에서 작성한 변경은 repository validation으로 확인합니다. MacBook production
  `auth init`, authenticated end-to-end smoke와 browser evidence는 장비 확보 뒤
  [POV-038](../tickets/POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md)의
  macOS same-origin `127.0.0.1:8080` runtime에서 닫습니다.

## Consequences

- POV-010은 native Windows auth 구현을 기다리지 않고 시작할 수 있습니다.
- Windows에서 전체 repository baseline이 통과해도 macOS production/browser evidence를
  대신하지 않습니다.
- MacBook 실기 검증은 POV-010 implementation delivery의 완료 조건이 아닙니다. Target
  MacBook을 사용할 수 없는 동안 POV-038을 `Backlog`로 유지합니다.
- POV-038 evidence 전에는 macOS production/dogfood 또는 installed-browser 지원을
  완료로 주장하지 않습니다.
- Local browser는 MacBook의 loopback same-origin에 접속합니다. LAN 노출, Windows에서
  MacBook backend로 직접 접속하는 개발 우회와 remote ingress는 이 결정에 포함되지 않습니다.

## Verification

- Windows: frontend baseline, Rust locked workspace check/test, targeted model-independent tests
- macOS/POV-038: production `auth init`, listener startup, local same-origin browser
  login/refresh/logout, text capture/readback, offline asset, cookie/storage/cache와 redaction
  evidence
- 공통: owner authority negative tests, duplicate submit, storage/revision conflict,
  `git diff --check`와 Markdown relative-link check

## Revisit Triggers

- Native Windows를 production backend로 지원해야 합니다.
- always-on backend가 macOS에서 다른 Unix 또는 cloud runtime으로 바뀝니다.
- Windows에서 authenticated end-to-end product flow를 실행해야 하는 요구가 생깁니다.
- remote ingress가 H5 이전에 명시적으로 재우선순위화됩니다.
