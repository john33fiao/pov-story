# POV-040 Reconcile macOS Raw Filename Validation

Status: Completed — 2026-08-01; target-macOS native Terminal locked workspace PASS

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

## Completion Evidence

Target MacBook의 native Terminal에서 macOS `26.5.2` (`25F84`, arm64), APFS,
Rust/Cargo `1.95.0` 조합을 검증했습니다. Base HEAD는
`89bd3cbf865835388e44b70f5db7554f2e54f0a3`이었고 locale은 `ko_KR.UTF-8`이었습니다.

- 수정 전 native Terminal의 두 raw filename test는 각각 exit `101`과
  `Illegal byte sequence (os error 92)`를 재현했고, 같은 경계의 process-supervisor suite는
  `22` PASS, `15` helper ignored, `0` FAIL로 exit `0`이었습니다.
- 별도 raw `fs::write` probe는 `ko_KR.UTF-8`, `C.UTF-8`, `C` 모두
  `ErrorKind::Uncategorized`와 `EILSEQ(92)`를 반환했습니다. 따라서 locale가 아니라 native
  Darwin/APFS filename 경계가 원인입니다. Codex managed temp 경계는 동일 작업을 먼저
  `EPERM(1)`/`PermissionDenied`로 거부해 기존 test가 platform-unavailable 분기로
  통과했습니다.
- Test-only filename capability 판정에 `Errno::ILSEQ`를 추가하고, EILSEQ는 허용하되
  unrelated `ENOENT`는 숨기지 않는 회귀 test를 추가했습니다. Production parser, artifact
  inventory, auth runtime과 schema는 변경하지 않았습니다.
- Raw name을 표현할 수 있는 filesystem에서는 기존 test가 raw bytes를
  `UnrecognizedPresent`/`Occupied`로 관찰하고 원본 artifact를 보존하는 assertions를 계속
  실행합니다. Native APFS의 EILSEQ 분기는 artifact가 생성되기 전의 capability 한계만
  기록하며 normalization, alias, adoption 또는 deletion을 허용하지 않습니다.

동일 native Terminal evidence set에서 다음 명령이 모두 exit `0`이었습니다.

- 새 EILSEQ 회귀 test와 두 named raw filename test
- `cargo test --locked -p pov-core --test process_supervisor -- --test-threads=1`
- `KDF_TEST_SERIAL=1 cargo test --locked --workspace --all-targets -- --test-threads=1`:
  전체 test binary 합계 `388` PASS, `17` ignored, `0` FAIL
- `cargo fmt --all -- --check`
- `cargo check --locked --workspace --all-targets`

이 완료는 POV-013의 historical exact-SHA matrix 결과를 덮어쓰지 않습니다. POV-013 full
matrix rerun과 POV-038 production/installed-browser evidence는 각 ticket에서 별도로 남습니다.

## Rollback

보안 contract를 완화하는 변경은 허용하지 않습니다. Corrective change가 raw artifact를
허용하거나 제거한다면 되돌리고 POV-013/038을 blocked 상태로 유지합니다.

## Links

- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-013](POV-013-conversation-core-offline-evidence-gate.md)
- [POV-038](POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md)
