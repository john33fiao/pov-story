# POV-031 Remove Password Blocklist Feature

Status: Completed — 2026-07-27; [ADR-0005](../decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md) Accepted and current-tree removal verified

Type: Security and compliance remediation

Roadmap: Cross-cutting H0/H1 maintenance

Depends on: [POV-034 completed](../deps/POV-034-restore-windows-workspace-validation-baseline.md); POV-005 accepted; current implemented POV-007 auth contract, not POV-007 completion

Blocks: None — POV-007의 이 선행 조건은 충족됐고 POV-032는 repository restart로 superseded

## Why

이 작업이 시작될 당시 repository는 침해 사고에서 수집·재배포된 password 후보를 변환한
plaintext blocklist를 source asset으로 포함했습니다. 각 문자열이 POV Story 사용자의
credential이나 account mapping은 아니었지만, 원천 데이터의 성격과 제3자 권리 범위가
public product repository에 계속 보존하기에 적절하지 않았습니다.

2026-07-26 당시 private 전환은 추가 공개 노출을 줄이는 containment일 뿐 이미 공개된
Git object, clone, fork와 cache를 회수하지 못했습니다. POV-031은 자료를 다른 corpus로
교체하지 않고 password blocklist 기능 자체를 current tree에서 제거했습니다.

## Decision

- offline/embedded password corpus와 caller-supplied blocklist context에 따른 새 password
  거부 기능을 제거합니다.
- 대체 password corpus나 network lookup을 도입하지 않습니다.
- NFC, exact 15~128 code-point grammar, NUL/invalid UTF-8 거부, Argon2id, secret zeroization,
  KDF admission, durable throttle와 recovery-code 계약은 유지합니다.
- ADR-0004의 blocklist 관련 결정은 구현 전에 새 ADR로 명시적으로 부분 supersede합니다.

2026-07-27 [ADR-0005](../decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md)가
Candidate 2와 exact `no-blocklist-check-v1` sentinel을 Accepted했습니다. Sentinel은
corpus evaluation 통과가 아니라 corpus evaluation을 주장하지 않는다는 의미입니다.

Common/compromised password 방어가 줄어드는 trade-off는 숨기지 않고 새 ADR과 release
review에 기록합니다.

## Removal-Time Coupling

제거 당시 이 기능은 asset 하나가 아니라 다음 persisted/runtime contract에 연결되어
있었습니다.

- `vendor/password-blocklist/`의 plaintext asset, manifest와 third-party notices
- `scripts/update-password-blocklist.mjs`의 deterministic updater와 filesystem self-test
- `crates/pov-core/src/auth/blocklist.rs`의 `include_bytes!`, digest validation과 rejection API
- `auth/mod.rs`의 module/export surface
- `auth/transition.rs` initialization metadata v1의 blocklist-version field와
  current/historical 분류
- `auth/secret_fs.rs`의 recovery/resume/rollback phase 판정
- `storage/auth_records.rs`의 initialization source-CAS, source fingerprint와 DB expectation
- `auth/maintenance.rs` 및 관련 tests의 current/historical fixtures
- 적용된 Conversation migration `0004`의
  `auth_password_credentials.blocklist_version`
- ADR-0004, Architecture, POV-007, README와 project-local RTD validation

당시 local audit에서 plaintext asset은 437개 후보, 8,161 bytes였습니다. Ticket과 log에는
후보 문자열을 복사하지 않았습니다.

## Scope

- embedded corpus, updater, notices와 blocklist enforcement API를 current tree에서 제거
- password bootstrap/change/recovery path가 corpus나 external source 없이 동작하도록 정리
- blocklist에만 쓰이는 current-version/digest contract 제거
- persisted metadata와 DB row를 안전하게 읽고 recovery할 compatibility contract 결정
- current/historical initialization reservation, source-CAS와 cleanup이 state confusion 없이
  fail closed하도록 typed outcome과 synthetic tests 갱신
- ADR-0004 partial supersession과 영향을 받는 Architecture, POV-007, README, TODO/WBS,
  local-only AGENTS/RTD validation 동기화
- current tree에 남는 third-party source, asset와 notice inventory 재검토

## Persisted Compatibility Gate

적용된 migration
`0004_local_auth_control_plane.sql`과 `0005_auth_throttle_bounds.sql`은 수정하거나 재사용하지
않습니다. 구현 전 ADR에서 다음 중 하나를 선택하고 fixture로 검증합니다.

1. metadata v1과 DB의 blocklist field는 legacy decoder/readback compatibility로만
   보존하고, 새 metadata version 또는 후속 migration은 blocklist 없는 policy를 기록합니다.
2. 기존 field를 명시적인 inert legacy provenance로 유지하되 새 write가 corpus 검사를
   수행했다고 주장하지 않도록 canonical sentinel과 semantics를 정의합니다.

[ADR-0005](../decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md)는
두 후보를 비교하고 두 번째 후보를 Accepted 결정으로 기록합니다. Metadata v1과 DB
persisted slot은 legacy policy provenance로 유지하고 신규 write는 exact sentinel만
생성합니다.

어느 선택이든 다음을 만족해야 합니다.

- 새 password 설정, startup와 recovery는 vendored plaintext나 network에 의존하지 않습니다.
- 기존 pre-source reservation을 forward/rollback할 수 있는 조건과 post-source lifecycle을
  typed outcome으로 구분합니다.
- legacy artifact를 새 policy로 조용히 재해석하거나 current artifact로 오인하지 않습니다.
- incompatible private pre-runtime artifact를 지원하지 않기로 하면 listener-closed cleanup
  또는 operator recovery 절차를 먼저 정의합니다.

## Out Of Scope

- Git history, GitHub cached view, fork, clone와 검색엔진 cache 제거
- force-push, remote branch 삭제 또는 GitHub Support 문의
- 새 password strength meter, online breached-password API, TOTP/WebAuthn 도입
- project `LICENSE` 추가 또는 과거 commit의 권리를 소급 변경
- production auth activation

## Acceptance Criteria

- HEAD에 `vendor/password-blocklist/`, updater, embedded corpus `include_bytes!`, corpus digest와
  password/context rejection API가 없습니다.
- 새 password는 제거된 corpus나 caller-supplied blocklist context만을 이유로 거부되지
  않으며 보존하기로 한 grammar/KDF/throttle/recovery 계약은 그대로 검증됩니다.
- 허용된 legacy decoder/migration 문맥 외의 blocklist enforcement reference가 없습니다.
- metadata v1과 이미 적용된 migration을 수정하지 않고 accepted ADR의 compatibility
  strategy로 기존 상태를 결정론적으로 처리합니다.
- 모든 current/historical initialization phase가 forward, rollback, operator action 또는
  fail-closed 중 하나로 명시되고 mixed state에서 listener를 열지 않습니다.
- current tree의 third-party inventory가 후속 MIT License 결정에 사용할 수 있게
  갱신됩니다.
- 영향받는 정본 문서와 실제 fast validation command가 같은 변경에서 동기화됩니다.

## Verification

- corpus/updater/module absence와 remaining references를 path/name search로 확인
- metadata codec, source observation/CAS, recovery/rollback/install/final-CAS/cleanup의
  current/historical synthetic suite
- password grammar, Argon2id, zeroization, KDF slot, throttle와 recovery regression suite
- clean checkout frontend/Rust fast validation, release build, smoke와 `git diff --check`
- built artifact가 removed corpus bytes나 corpus-derived version을 포함하지 않는지 확인

실행 시 제거된 updater 명령을 validation list에서 먼저 삭제한 뒤, 실제 존재하는 명령만
실행·보고합니다.

## Rollout And Rollback

POV-031은 당시 별도 history-remediation 절차보다 먼저 reviewable current-tree
변경으로 완료했습니다. Persisted state를 보존하는 application rollback 경계는
[ADR-0005](../decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md)를
따릅니다.

2026-07-27 sanitized current tree만 새 public repository history에 반입했습니다. 기존
history-remediation 계획은
[POV-032](POV-032-purge-password-blocklist-history-and-caches.md)에 superseded closure로
보존하며 현재 저장소 운영 정책은 corpus 복원이나 old history force-push를 rollback
경로로 두지 않습니다.

## License Boundary

POV-031 완료 뒤 current tree의 code, asset, generated material과 notice를 inventory하고
project-owned 범위에 MIT License를 적용했습니다. Rust/npm dependency와 그 license
metadata는 dependency-owned 범위로 유지하며 MIT 적용은 기존 third-party material이나
과거 commit의 권리를 소급해 바꾸지 않습니다. 외부 contribution policy는 별도
미결정입니다.

## Completion Evidence

- `vendor/password-blocklist/`, updater, embedded module/export, corpus digest와
  enforcement API를 current tree에서 제거했습니다.
- Metadata v1 wire slot과 migration `0004`의 persisted column은 유지하되 application
  내부에서는 legacy policy provenance로 취급하고 신규 metadata/DB write에 exact
  `no-blocklist-check-v1`을 사용합니다.
- Sentinel complete stage/prepared만 source resume 가능하고 모든 legacy pre-source는
  rollback-only입니다. Exact legacy post-source는 rewrite 없이 install/final-CAS/cleanup
  forward-only로 완료합니다.
- Stable canonical metadata/DB mismatch는 evidence를 보존한 typed `Blocked`,
  source-shape·filesystem·store·context drift는 poison/fail-closed로 검증했습니다.
- Source fingerprint, pre-writer durability fence, source/final-CAS response-loss
  classification, no-replace publish와 deletion-only cleanup ordering을 유지했습니다.
- Password grammar, Argon2id, zeroization, KDF admission, throttle와 recovery regression을
  유지했습니다.
- Current-tree inventory에서 별도 vendored source asset/notice는 남지 않았습니다.
  Rust/npm dependency declaration과 dependency-owned license metadata는 남으며 project
  code에는 MIT License를 적용했고 contribution policy는 별도 결정입니다.
- Windows 전체 workspace와 Ubuntu WSL Unix auth maintenance suite, release build,
  smoke, frontend 검증과 removal/binary 검사를 완료 조건으로 실행했습니다.

POV-031은 current tree 제거와 persisted compatibility를 완료했습니다. 이후 repository
restart에서 기존 Git graph를 반입하지 않았으므로 history rewrite는 현재 저장소의 pending
작업이 아닙니다. 이 결론과 외부 copy에 대한 보증 한계는
[POV-032](POV-032-purge-password-blocklist-history-and-caches.md)에 보존합니다.
