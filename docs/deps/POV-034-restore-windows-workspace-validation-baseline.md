# POV-034 Restore Windows Workspace Validation Baseline

Status: Completed — 2026-07-27

Type: Corrective maintenance

Roadmap: Cross-cutting H0/H1 build and validation baseline

Depends on: POV-001 completed

Completion unblocks: POV-031 compatibility decision and implementation verification, POV-033 implementation readiness, Windows completion evidence for POV-007

## Why

문서화된 Rust fast suite는 clean checkout의 현재 workspace를 compile하고 test할 수 있어야
합니다. Windows reference 환경에서는 auth storage module이 모든 platform에서 compile되는
반면 해당 module이 사용하는 lifecycle과 test-fault type은 Unix에만 정의되어, 고정
toolchain이 test 실행 전에 실패합니다.

이는 Windows authentication 활성화 요청이 아니라 verification baseline 회귀입니다.
이 불일치를 복구하기 전에는 POV-031이 clean pre-change baseline을 만들거나 요구된 전체
validation evidence를 제출할 수 없습니다.

## What

현재 POV-007 auth storage와 maintenance 구현의 platform compile 경계를 일관되게
복구합니다. Windows는 generic workspace를 compile할 수 있어야 하지만, 지원되지 않는
Unix auth maintenance capability는 계속 unavailable이고 fail closed여야 합니다.

cross-platform schema/storage compile과 Unix-only auth maintenance 동작을 구분하는 regression
evidence를 추가합니다. 변경은 POV-031 전에 독립적으로 review·validate할 수 있는 작은
단위로 유지합니다.

## Observed Evidence

구현 전 HEAD를 Windows에서 확인한 결과:

- `cargo check --locked -p pov-core`는 `storage/auth_records.rs`의 unresolved import로
  실패합니다.
- `cargo check --locked --workspace --all-targets`도 같은 경계에서 실패합니다.
- `cargo test --locked -p pov-core --lib`는 test 실행 전에 실패하고 Unix-only test-fault
  type도 같은 문제로 드러냅니다.
- `storage.rs`는 platform gate 없이 `auth_records`를 포함하지만 import 대상 lifecycle과
  mutation type은 `cfg(unix)` 또는 `cfg(all(test, unix))`입니다.

전체 compiler output은 diagnostic evidence로만 취급하고 이 ticket에 복사하지 않습니다.

## Scope

- 현재 auth storage 구현의 module, import, type과 test compile gate 정렬
- Windows에서 generic Conversation migration과 store lifecycle compile 보존
- Unix auth initialization maintenance 동작과 typed fail-closed outcome 유지
- non-Unix gate drift를 탐지하는 compile/test coverage 추가 또는 갱신
- README, Architecture, TODO/WBS와 영향받는 ticket dependency 동기화

## Out Of Scope

- Windows auth maintenance, login, JWT, refresh, HTTP 또는 runtime 구현
- POV-033이 소유하는 Windows Job Object, Python Whisper 또는 model/provider 작업
- POV-031이 소유하는 password blocklist compatibility와 제거
- migration `0004`/`0005` 변경
- production auth 활성화
- 광범위한 storage 또는 platform refactor

## Acceptance Criteria

- Windows `cargo check --locked -p pov-core`가 platform-gated auth unresolved import나 관련
  unused-import warning 없이 성공합니다.
- 필요한 frontend build 뒤 Windows workspace check와 test command가 current locked
  manifest로 성공합니다.
- 지원되지 않는 Windows auth maintenance capability가 노출되거나 성공 stub으로 제공되거나
  `pov-api`에 연결되지 않고 unavailable·fail-closed 상태를 유지합니다.
- 기존 Unix auth maintenance code와 synthetic contract는 의도한 target에서만 활성화되고
  관련 Unix validation을 통과합니다.
- Conversation migration, persisted auth schema와 runtime 동작은 바뀌지 않습니다.
- POV-031/033 dependency와 현재 verification 상태가 영향받는 정본 문서에서 일치합니다.

## Verification

```bash
npm --prefix web run build
cargo fmt --all -- --check
cargo check --locked -p pov-core
cargo test --locked -p pov-core --lib
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
git diff --check
```

완료 전 사용 가능한 Unix target에서 관련 auth storage와 maintenance suite를 실행합니다.
해당 target evidence를 확보할 수 없으면 PASS로 추정하지 않고 ticket을 열린 상태로 유지하며
미검증 platform 범위를 보고합니다.

## Implementation Evidence

- `storage/auth_records.rs`, 이를 소비하는 storage binding/type과 crate-private transition
  re-export는 같은 `cfg(unix)` 경계에서만 compile됩니다.
- non-Unix에서는 auth maintenance capability를 compile하거나 stub으로 제공하지 않지만,
  generic Conversation store는 migration `0004`/`0005`를 계속 적용합니다.
- non-Unix synthetic regression은 migration `1..5`의 exact ordered report와 canonical
  `auth_key_lifecycle`의 `uninitialized` singleton을 검증합니다.
- `pov-api`, auth schema, persisted contract와 migration `0004`/`0005`는 변경하지 않았습니다.

## Completion Evidence

- Windows Rust `1.95.0`: `cargo check --locked -p pov-core`,
  `cargo test --locked -p pov-core --lib`,
  `cargo check --locked --workspace --all-targets`,
  `cargo test --locked --workspace --all-targets` PASS.
- Ubuntu WSL Rust `1.95.0`: `cargo check --locked -p pov-core`와
  `cargo test --locked -p pov-core --lib` PASS. Unix lib suite는 241 passed, 1 ignored이며
  ignored 항목은 subprocess helper entry입니다.
- frontend format/lint/typecheck/build, Windows release smoke와 `git diff --check` PASS.

## Rollback

migration과 persisted state를 보존하면서 platform-boundary repair만 되돌립니다. Rollback은
Windows를 알려진 build-blocked 상태로 되돌려 POV-031과 POV-033을 다시 gate하며 alternate
auth path를 활성화하지 않습니다.

## Links

- [POV-001](POV-001-local-offline-walking-skeleton.md)
- [POV-007](../tickets/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-031](POV-031-remove-password-blocklist-feature.md)
- [POV-033](../tickets/POV-033-windows-python-whisper-turbo-provider.md)
- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [README](../../README.md)
