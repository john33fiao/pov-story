# POV-032 Purge Password Blocklist History And Caches

Status: Superseded — 2026-07-27 repository restart

Type: Security and privacy remediation archive

Roadmap: Repository safety baseline

Depends on: [POV-031 completed](POV-031-remove-password-blocklist-feature.md)

Blocks: None

## Original Purpose

이 ticket은 POV-031의 current-tree 제거와 별도로 기존 저장소의 affected Git history,
remote reference와 cache를 inventory하고 필요하면 destructive rewrite를 수행하기 위해
작성했습니다. Current-tree 삭제만으로 과거 clone, fork, cache나 Git object가
회수됐다고 볼 수 없다는 경계를 명시하려는 계획이었습니다.

## Supersession Decision

2026-07-27 sanitized current tree만 새 public repository history에 반입해 저장소를 다시
시작했습니다. 기존 저장소의 Git graph를 새 저장소로 가져오지 않았으므로 이 ticket이
계획한 filter-repo, force-push, remote ref cleanup과 GitHub Support 절차는 현재
저장소에 적용할 대상이 없습니다.

따라서 이 ticket은 실행 완료가 아니라 repository replacement로 superseded됐습니다.
파괴적 history 작업 권한을 부여하지 않으며 현재 저장소에 pending maintenance gate를
남기지 않습니다.

## Current Repository Evidence

2026-07-27 기준 다음 read-only evidence를 확인했습니다.

- GitHub repository metadata에서 `john33fiao/pov-story`는 public입니다.
- local `master`와 locally cached `origin/master`가 같은 tip을 가리키며 GitHub metadata의
  default branch는 `master`입니다.
- 재시작 시점 reachable history는 README, LICENSE, sanitized project import로 구성된
  세 commit뿐입니다.
- `git rev-list --objects --all`에 과거 `vendor/password-blocklist/`,
  `scripts/update-password-blocklist.mjs`와
  `crates/pov-core/src/auth/blocklist.rs` 경로가 없습니다.
- `git fsck --full --unreachable --no-reflogs`에서 unreachable object가 발견되지
  않았습니다.
- 추적 파일에서 원본 corpus, updater, embedded blocklist implementation, 명백한 token,
  개인 absolute path와 과거 session identifier가 발견되지 않았습니다.
- ADR, immutable migration과 source compatibility에 남은 blocklist 명칭은
  [ADR-0005](../decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md)의
  sentinel/legacy persistence contract입니다.

## Verification Boundary

이 evidence는 현재 저장소의 reachable object, local object database와 추적 파일만
설명합니다. 이전 저장소에서 제3자가 만들었을 수 있는 clone, fork, cache, screenshot,
search index 또는 offline archive가 없음을 증명하지 않습니다. 검색 결과가 없다는
사실도 외부 copy 회수 완료의 충분조건으로 사용하지 않습니다.

이번 supersession은 Git history rewrite, remote visibility 변경, commit author metadata
수정, 외부 copy 삭제나 MIT License의 과거 third-party material 소급 적용을 포함하지
않습니다.

## Closure Criteria

- 현재 저장소 active 문서에 private containment나 history rewrite 대기 상태가 없습니다.
- README, TODO, WBS, ADR-0005와 POV-031이 이 superseded archive를 일관되게 참조합니다.
- 현재 reachable history와 추적 파일에 위 target path와 corpus가 없습니다.
- project-owned code의 MIT 적용과 dependency-owned license 경계가 별도로 기록됩니다.
- 외부 contribution policy만 unresolved project-operation question으로 유지됩니다.

## References

- [POV-031](POV-031-remove-password-blocklist-feature.md)
- [ADR-0005](../decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md)
- [README](../../README.md)
- [TODO](../TODO.md)
- [Roadmap](../WBS.md)
