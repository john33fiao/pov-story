# POV-032 Purge Password Blocklist History And Caches

Status: Planned — POV-031 dependency completed; blocked by explicit destructive-action approval

Type: Security and privacy remediation

Roadmap: Cross-cutting repository safety

Depends on: [POV-031 completed](../deps/POV-031-remove-password-blocklist-feature.md), repository private containment confirmed

Blocks: public visibility review

## Why

Current tree에서 파일을 삭제해도 Git history의 object, branch, pull-request reference,
fork, clone와 cached view에는 plaintext password candidates가 남을 수 있습니다. Repository
private 전환은 새 unauthenticated access를 줄이지만 이미 만들어진 외부 copy를 삭제하지
않습니다.

이 ticket은 기능 제거와 분리해 destructive history rewrite, remote cleanup과 잔존 노출
검증을 명시적 maintenance 작업으로 수행합니다.

## Known Exposure Boundary

2026-07-26 23:46~23:53 KST 기준 read-only audit:

- user가 repository를 private으로 전환했다고 확인했습니다.
- unauthenticated repository, public API, known raw notice/asset와 known
  introduction-commit URL은 모두 HTTP `404`를 반환했습니다.
- GitHub public repository·filename·commit search, Bing 일반 web 검색과
  `site:grep.app` 검색에서 exact repository/path/file/identifier 관련 결과를 찾지
  못했습니다. grep.app direct API는 challenge `429`로 미확인입니다.
- Sourcegraph global index를 public fork와 archived repository까지 확장했지만 known
  path/file/identifier match를 찾지 못했습니다.
- Internet Archive CDX의 repository/raw wildcard 결과는 모두 빈 목록이었고 repository,
  known commit, notice와 raw asset Availability API도 archived snapshot을 반환하지
  않았습니다.

이 결과는 확인 시점의 public discoverability에 대한 negative evidence일 뿐, 과거에
색인되지 않았거나 clone/fork/cache/screenshot이 없다는 증거가 아닙니다. Search index
지연, 개인화, 지역별 결과와 이미 저장된 copy는 이 검사로 배제할 수 없습니다.

Old object ID, commit ID와 corpus 문자열은 public-facing ticket, issue, support-free log나
검색 query 결과에 복제하지 않습니다. Rewrite 실행에 필요한 exact identifier는 private
maintenance record와 GitHub Support 요청에만 최소 범위로 기록합니다.

## Scope

### 1. Freeze And Inventory

- push freeze와 maintenance window를 선언하고 open work를 정리
- access-controlled mirror/backup을 만들고 복구 책임자와 보존·폐기 시점을 기록
- remote heads, tags, pull-request refs, release, Actions artifact/log, Pages/package와 fork
  network를 다시 열거
- 모든 reachable ref에서 `vendor/password-blocklist/`의 과거 path/rename과 raw-data object를
  inventory
- POV-031 이후 sanitized current tree와 retained third-party notices를 확인

### 2. Rewrite

- fresh mirror clone에서 current `git-filter-repo --sensitive-data-removal` 또는 reviewed
  sanitized-history replacement 중 더 작은 안전한 절차를 선택
- 최소 필수 대상은 모든 ref의 `vendor/password-blocklist/` 전체입니다.
- updater와 non-data blocklist implementation history도 제거할지는 rebuildability,
  disclosure와 rewritten-history 크기를 비교해 execution plan에 명시합니다.
- raw corpus 자체를 replace-text input, shell argument, CI log나 public artifact에
  복제하지 않습니다.
- changed refs, first changed commits, affected PR count와 orphaned LFS 여부를 private
  execution record에 남깁니다.

### 3. Publish And Remote Cleanup

- explicit user approval 뒤 reviewed rewritten refs만 force-push
- obsolete remote branch/tag를 정리하고 collaborators가 old clone을 merge/push하지 않도록
  fresh clone 또는 documented cleanup을 요구
- old raw/commit URL, branch/tag와 GitHub search가 unauthorized public access를 허용하지
  않는지 재검증
- pull-request refs나 cached SHA view가 남으면 GitHub의 sensitive-data-removal 요건과
  영향 범위를 검토한 뒤 Support에 dereference, garbage collection과 cached-view removal을
  요청
- 실제 검색 결과나 cached URL이 발견될 때만 해당 검색엔진의 removal 절차와 결과를 기록

GitHub Support가 이 자료를 지원 대상 sensitive data로 인정한다는 보장은 없습니다. 지원
요청은 rewrite와 ref cleanup을 대신하지 않습니다.

## Rewrite Decision Gate

실행 계획은 다음 두 후보를 비교하고 승인받습니다.

1. 모든 affected ref에 path filtering을 적용하고 build가 깨진 historical commit을
   허용하되 current sanitized tree를 보존
2. 최초 도입 직전의 reviewed safe base와 POV-031의 sanitized current tree를 이용해 짧은
   replacement history를 만들고 obsolete remote branch를 폐기

선택 전에 changed commit 수, open/closed PR diff 손상, 서명·link·automation 영향,
recontamination risk와 rollback cost를 문서화합니다. 어느 방법도 이 ticket 등록만으로
force-push 권한을 부여하지 않습니다.

## Out Of Scope

- 다른 사람이 이미 만든 clone, screenshot나 offline archive를 원격에서 강제로 삭제
- secret rotation: 이 자료는 POV Story account credential mapping이 아닙니다.
- MIT 또는 다른 project license를 과거 commit에 소급 적용
- public visibility 재활성화

## Acceptance Criteria

- fresh clone의 모든 reachable head/tag와 locally obtainable PR ref에서 target path와
  identified raw-data object가 발견되지 않습니다.
- POV-031의 sanitized current tree와 tests가 rewritten default branch에서 재현됩니다.
- old branch/tag/raw URL은 unauthenticated access가 불가하고 public code/commit search에서
  target을 찾지 못합니다.
- affected PR, detached public fork, Actions artifact/log, release와 archive 상태가
  `clean`, `not present`, `owner action required` 또는 명시적 residual로 기록됩니다.
- GitHub Support와 검색엔진 removal은 `not needed`, `requested`, `completed`, `denied` 또는
  `unverifiable` 중 하나와 근거를 가집니다.
- collaborators가 old history를 다시 push하지 않도록 fresh-clone/cleanup 확인을 마칩니다.
- repository는 별도 public visibility review가 승인될 때까지 private로 유지됩니다.

## Verification

- `git rev-list --objects --all`과 모든 remote/ref inventory에서 target path/object absence
- fresh clone에서 current source, migration prefix, full fast validation, release build와 smoke
- unauthenticated repository/raw/known-old-commit HTTP status 재확인
- exact repository/path 중심의 GitHub, 일반 web 검색과 Internet Archive 재확인
- `git-filter-repo` changed-ref report와 GitHub Support outcome을 private execution record와
  redacted ticket evidence로 교차 확인

검색 결과 없음은 회수 완료의 충분조건으로 사용하지 않습니다.

## Rollback And Residual Risk

Rewrite 전 sealed backup은 private access-controlled 위치에서만 복구용으로 유지하고
retention 종료 시 별도 폐기합니다. 실패하면 private 상태에서 sanitized refs를 다시
만들며 tainted history를 public으로 복원하지 않습니다.

History rewrite 뒤 commit SHA, 기존 link, PR diff, commit/tag signature와 automation
reference가 깨질 수 있습니다. 이미 생성된 clone, fork, screenshot와 외부 archive는
회수할 수 없으며 GitHub Support나 검색엔진도 삭제를 보장하지 않습니다.

## References

- [GitHub: Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [GitHub: Setting repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)
- [Internet Archive Wayback Availability API](https://archive.org/wayback/available)
