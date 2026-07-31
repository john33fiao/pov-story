# POV-040 Reconcile macOS Raw Filename Validation

Status: Planned — opened by POV-013 `fix`

Type: Corrective platform validation

Roadmap: H1 platform evidence

Depends on: POV-007, POV-034

Blocks: POV-013, POV-038

## Why

POV-013 target의 KDF-serialized full workspace suite는 Codex sandbox 안에서 process-group
signal이 `PermissionDenied`로 실패했고, process 권한을 허용한 host execution에서는 아래
두 raw non-UTF-8 filename test가 `Illegal byte sequence (os error 92)`로 실패했습니다.

- `auth::maintenance::tests::clean_inspection_is_read_only_and_any_non_lock_artifact_is_occupied`
- `auth::secret_fs::tests::raw_non_utf8_artifact_name_is_occupied_without_normalization`

두 raw filename test는 sandbox에서 단독 PASS했고 process-supervisor suite는 host에서 단독
PASS했지만, required full command가 한 execution boundary에서 exit `0`을 만들지 못했습니다.

## Scope

- target MacBook의 native Terminal에서 exact full command와 두 targeted test를 재현
- filesystem, locale, process launcher와 Codex execution boundary 차이를 식별
- raw non-UTF-8 artifact를 alias로 받지 않고 evidence-preserving fail closed하는 contract 유지
- 필요하면 test/harness만 current macOS behavior에 맞추고 same-path security regression 추가

## Out Of Scope

- raw filename normalization 또는 자동 삭제
- unknown artifact 허용
- instance-directory permission/ACL 완화
- Windows auth runtime 활성화

## Acceptance Criteria

- 한 documented target-macOS execution boundary에서
  `KDF_TEST_SERIAL=1 cargo test --locked --workspace --all-targets -- --test-threads=1`이 exit
  `0`으로 완료됩니다.
- process cleanup suite와 두 raw filename test가 같은 evidence set에서 PASS합니다.
- unsupported raw name은 보존되고 auth initialization/runtime은 fail closed합니다.
- 환경 한계라면 exact prerequisite와 reproduction이 문서화되고 unsupported 조합을 PASS로
  표시하지 않습니다.

## Verification

- two named targeted Rust tests
- `cargo test --locked -p pov-core --test process_supervisor -- --test-threads=1`
- KDF-serialized locked workspace test
- `cargo fmt --all -- --check`
- `cargo check --locked --workspace --all-targets`
- `git diff --check` and relative Markdown-link check

## Rollback

보안 contract를 완화하는 변경은 허용하지 않습니다. Corrective change가 raw artifact를
허용하거나 제거한다면 되돌리고 POV-013/038을 blocked 상태로 유지합니다.

## Links

- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-013](POV-013-conversation-core-offline-evidence-gate.md)
- [POV-038](POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md)
