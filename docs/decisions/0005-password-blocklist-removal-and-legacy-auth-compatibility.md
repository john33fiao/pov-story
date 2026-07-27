# ADR-0005: Password Blocklist Removal And Legacy Auth Compatibility

- Status: Accepted
- Date: 2026-07-27
- Decision ticket:
  [POV-031](../deps/POV-031-remove-password-blocklist-feature.md)
- Partially supersedes:
  [ADR-0004](0004-local-authentication-and-session-security-contract.md)

2026-07-27 사용자 승인으로 Candidate 2와 아래 compatibility·residual-risk 경계를
채택했습니다. 이 ADR은 ADR-0004의 blocklist-specific 계약만 부분 supersede하며,
나머지 authentication/session 계약은 그대로 유지합니다.

같은 날 sanitized current tree를 새 public repository history에 반입해 저장소를 다시
시작했습니다. 이 ADR의 persisted compatibility 결정은 계속 유효하지만 기존 history
정리 계획인 [POV-032](../deps/POV-032-purge-password-blocklist-history-and-caches.md)는
현재 저장소에 적용할 대상이 없어 superseded archive로 닫혔습니다.

## Context

POV-031은 password blocklist corpus, updater와 enforcement API를 current tree에서
제거하되 이미 적용된 auth persistence와 crash-recovery 계약을 보존해야 합니다. 현재
구현은 corpus 자체와 별도로 다음 persisted coupling을 가집니다.

- initialization metadata v1은 `blocklist_version` field를 필수로 encode합니다.
- Conversation migration `0004`의
  `auth_password_credentials.blocklist_version`은 `TEXT NOT NULL`입니다.
- initialization source-CAS는 metadata 값을 같은 DB field에 기록하고 commit 전에
  canonical source를 다시 읽습니다.
- source fingerprint는 DB field의 실제 bytes를 포함합니다.
- pre-source `StagedComplete|Prepared`는 compiled current marker일 때만 resume할 수
  있고 다른 canonical marker는 rollback-only입니다.
- source가 이미 commit된 `initializing|active` artifact는 metadata와 DB source가
  byte-exact이고 기존 filesystem identity, staged linkage, active-key equality와
  phase-shape invariant가 모두 유효할 때 marker가 historical이어도 install, final
  CAS와 cleanup을 forward-only로 완료합니다.

Password의 NFC, UTF-8, NUL, 15~128 code-point grammar, Argon2id verifier,
secret zeroization, KDF admission, durable throttle와 recovery-code contract는
blocklist module과 분리돼 있습니다. Blocklist 제거는 이 계약을 변경하지 않습니다.

Migration `0004`와 `0005`는 적용된 immutable prefix입니다. 수정하거나 번호를
재사용할 수 없으며, source field를 없애려면 후속 migration과 별도 downgrade·recovery
계약이 필요합니다.

## Decision Drivers

- 신규 write가 corpus 검사를 수행했다고 거짓으로 주장하지 않아야 합니다.
- legacy metadata와 DB row를 새 정책으로 조용히 rewrite하거나 재해석하지 않아야
  합니다.
- clean, pre-source, post-source와 mixed state가 rollback, forward recovery,
  operator action 또는 fail-closed 중 하나로 결정론적으로 분류돼야 합니다.
- migration `0004`/`0005`, source-CAS, source fingerprint와 commit-uncertainty
  classifier를 약화하지 않아야 합니다.
- corpus, updater, digest와 enforcement code를 current tree에서 완전히 제거할 수
  있어야 합니다.
- application rollback 시 새 persisted state를 구버전 decoder가 가능한 한 안전하게
  처리해야 합니다.
- 당시 POV-031을 가장 작은 reviewable current-tree 변경으로 유지하고 별도 승인이
  필요했던 history-remediation 절차를 섞지 않아야 합니다.

## Compatibility Candidates

### Candidate 1: Metadata v2 Or Follow-up Migration

Metadata v1과 기존 DB field를 legacy decoder/readback으로만 유지하고, 새 metadata
version 또는 후속 migration에 blocklist가 없는 policy를 기록합니다.

장점은 새 policy를 새 field와 type으로 명확히 표현하고 장기적으로 잘못 이름 붙은
schema를 정리할 수 있다는 점입니다. 그러나 metadata v2만 추가해서는 migration
`0004`의 `NOT NULL` field를 생략할 수 없습니다. 기존 field에 어떤 값을 계속 쓰면
storage 전략은 결국 Candidate 2의 sentinel 방식과 같아집니다.

기존 field를 실제로 legacy readback-only로 만들려면 후속 migration에서 credential
table을 rebuild해 field를 제거하거나 nullable로 바꾸거나, 신규 credential table로
write authority를 이전해야 합니다. Side policy column/table만 추가해도 기존
credential row의 `NOT NULL` field는 채워야 하므로 이 문제를 해결하지 못합니다.
기존 field에 sentinel을 계속 쓰면 Candidate 2와 결합한 전략입니다. Pure Candidate
1에는 다음 변경이 함께 필요합니다.

- v1/v2 metadata dispatch와 staged-artifact linkage
- version별 source seed와 expectation
- 후속 migration과 migration-count fixture, 새 table을 추가할 경우 exact auth table
  inventory
- legacy/new source shape와 fingerprint domain
- source-CAS, commit-uncertainty classifier와 final lifecycle CAS
- 구버전 binary가 future metadata/migration을 만났을 때의 operator recovery

구버전 binary는 완성된 metadata v2를 invalid/unsupported artifact로 분류해
pre-source exact rollback조차 수행하지 못할 수 있습니다. 후속 migration도 구버전의
exact migration history 검증에서 future state가 됩니다. 따라서 이 후보는 장기
schema는 깨끗하지만 POV-031에서 recovery surface와 downgrade boundary를 동시에 크게
바꿉니다.

### Candidate 2: Existing Field With An Inert Canonical Sentinel

Metadata v1 wire shape와 migration `0004`의 DB field를 유지하되, 신규 write에는
corpus 검사를 주장하지 않는 canonical sentinel을 기록합니다. 기존 canonical
marker는 opaque legacy provenance로만 decode하고 byte-exact readback에 사용합니다.

이 후보는 기존 historical-state contract를 그대로 활용합니다.

- 새 sentinel metadata의 complete pre-source state만 current policy입니다.
- legacy pre-source state는 source로 전진시키지 않고 rollback-only로 유지합니다.
- 이미 source가 commit된 legacy state는 metadata와 DB가 exact하고 기존 filesystem과
  phase invariant가 모두 유효하면 forward-only로 완료합니다.
- metadata와 DB marker가 다르면 기존 exact matcher가 mismatch로 분류합니다.
- source fingerprint에 실제 marker bytes가 계속 포함돼 mismatch-to-mismatch drift도
  탐지합니다.
- migration, source-CAS transaction shape, final CAS와 cleanup ordering은 그대로
  유지합니다.
- 구버전 binary는 sentinel을 canonical historical marker로 읽어 pre-source에서는
  rollback-only, exact post-source에서는 forward-only로 처리할 수 있습니다.

비용은 `blocklist_version`이라는 legacy field name과 metadata v1 slot이 남는다는
schema debt입니다. 이 debt는 compatibility를 제거할 수 있는 별도 evidence와
후속 ADR/migration에서 정리합니다.

## Decision

Candidate 2를 채택합니다.

### Partial Supersession Boundary

이 ADR은 ADR-0004의 다음 blocklist-specific 계약만 부분 supersede합니다.

- bootstrap, recovery와 password change의 새 password를 versioned offline corpus와
  caller-supplied blocklist context로 거부하는 규칙
- initialization metadata v1이 compiled blocklist version을 current marker로
  기록한다는 의미
- current/historical blocklist 분류를 pre-source resume eligibility로 사용하는 규칙
- `AUTH-PASS-02`의 blocked-candidate rejection과 blocklist-update case

`AUTH-PASS-02`의 unique salt, exact PHC parameter, unsupported stored verifier와 기존
hash login 관련 검증은 유지합니다. Metadata v1 wire shape, password grammar,
Argon2id, recovery, throttle, key lifecycle, source transaction, JWT, session, cookie,
CSRF와 redaction 계약도 변경하지 않습니다.

ADR-0004에는 이 partial supersession과 유지되는 계약 범위를 링크로 동기화합니다.

### Canonical Sentinel And Semantics

신규 initialization metadata v1과 DB write의 canonical sentinel은 exact ASCII
`no-blocklist-check-v1`입니다.

이 값의 유일한 의미는 다음과 같습니다.

> 이 credential initialization write는 password corpus evaluation을 주장하지 않는다.

이 sentinel은 다음 의미가 아닙니다.

- password가 common 또는 compromised corpus 검사를 통과했다.
- 과거 corpus의 특정 version이나 digest가 사용됐다.
- password strength 또는 account-context 검사가 수행됐다.
- credential이 production listener에 사용할 수 있다.

Sentinel은 corpus, updater, digest나 network lookup과 독립된 persistence constant로
소유합니다. 제거 대상 blocklist module이 sentinel을 소유하면 안 됩니다.

Persisted wire field와 DB column name은 compatibility 때문에 유지하지만, application
code에서는 이를 `legacy policy provenance`로 취급합니다. 신규 encoder/writer만
sentinel을 생성합니다. 다른 canonical metadata v1 value는 legacy provenance이며
신규 write에 사용하지 않습니다.

### Legacy Decode And Readback

- Metadata v1 decoder는 기존 canonical provenance bytes를 lossless하게 보존합니다.
- Legacy value를 sentinel로 rewrite, normalize 또는 alias하지 않습니다.
- Legacy value의 실제 corpus, digest 또는 updater를 재검증하지 않습니다.
- Legacy value는 metadata와 DB의 exact equality, source fingerprint와 recovery
  classification에만 사용합니다.
- Retained source expectation이 있는 `initializing|active`에서 canonical grammar를
  통과하지 못하는 DB value나 source-shape corruption은 storage error입니다.
- Invalid metadata checksum, invalid staged linkage와 안전하게 관찰된 illegal artifact
  combination은 typed `Blocked` 또는 underlying filesystem error로 fail closed합니다.
  `Blocked` 자체를 poison error로 재분류하지 않습니다.

### New Initialization Write

- Clean `uninitialized` state에서 만드는 metadata v1은 sentinel을 기록합니다.
- Source-CAS는 metadata의 same sentinel을 기존 DB field에 transactionally 기록합니다.
- Commit 전 canonical source readback, response-loss classification과 final CAS는
  marker bytes를 포함한 기존 exact matcher를 사용합니다.
- Corpus 또는 caller-supplied blocklist context 때문에 새 password를 거부하지
  않습니다.
- Password grammar, verifier, recovery, throttle와 secret-handling 계약은 그대로
  적용합니다.

### Recovery And Rollback

- 새 sentinel metadata의 `StagedComplete|Prepared` pre-source state만
  resume-or-rollback candidate입니다.
- Reservation-only 또는 metadata-incomplete pre-source state에서는 policy marker를
  관찰할 수 없으며 rollback-only입니다. Sentinel이 decode된 metadata-complete,
  staged-incomplete와 metadata-only state도 rollback-only입니다.
- 모든 legacy pre-source phase는 rollback-only입니다. Legacy `Prepared`를 source로
  commit하지 않습니다.
- Legacy pre-source rollback 뒤에는 password와 replacement recovery code를 다시
  입력·표시·확인해 sentinel 기반 initialization을 새로 시작합니다.
- Source가 이미 commit된 legacy `initializing|active` state는 rollback하지 않습니다.
  Retained metadata와 DB source가 exact하고 filesystem identity, staged linkage,
  active-key equality와 phase-shape invariant가 모두 유효할 때만 install, final CAS와
  cleanup을 forward-only로 완료합니다.
- Stable canonical mismatch는 typed `Blocked`로 evidence를 보존하고 operator action을
  요구합니다. 자동 rollback, forward, rewrite 또는 cleanup을 하지 않으며 POV-031의
  startup wiring은 이 상태를 listener-ready로 승인하면 안 됩니다.
- Recognized invalid metadata/checksum, staged linkage와 안전하게 관찰된 illegal
  artifact combination은 typed `Blocked`일 수 있습니다. Unsafe file type, mode 또는
  identity race, retained expectation 구간의 DB source-shape corruption,
  migration/history drift, A/B observation drift와 underlying filesystem/store/context
  error는 store/actor를 poison하고 fail closed합니다.

### Migration, CAS And Fingerprint

- Migration `0004`와 `0005`를 수정하거나 재사용하지 않습니다.
- 이 결정만을 위한 새 migration을 추가하지 않습니다.
- Existing source fingerprint domain과 field coverage를 유지합니다. Sentinel과
  legacy provenance는 서로 다른 actual bytes로 자연스럽게 구분됩니다.
- Source-CAS는 clean exact predicate에서 sentinel source만 새로 commit합니다.
- Final lifecycle CAS는 current 또는 legacy 여부가 아니라 metadata와 full source의
  exact equality를 요구합니다.
- Post-source `initializing`, 또는 initialization `active`에서 retained metadata
  expectation이 남아 있는 recovery 구간은 source fingerprint와 exact source를 계속
  재검증합니다.
- Cleanup command는 metadata를 삭제한 뒤에도 삭제 전 retained metadata/DB snapshot을
  보존하고, 빈 cleanup directory 제거와 terminal 확인까지 exact source를
  재검증합니다.
- Metadata 삭제 뒤 crash/restart해 빈 cleanup directory만 남으면 source observation은
  `NotApplicable`이고 상태는 `AwaitingCleanupDirectoryRemoval`입니다. 이때는 active
  lifecycle, KID, keyring version, active key와 namespace invariant로 directory removal을
  재개합니다.
- Cleanup directory까지 사라진 subsequent inspection의 `InitializationComplete`는
  좁은 protocol terminal입니다. Sentinel이나 legacy provenance를 재증명하지 않으며
  auth validity 또는 listener readiness로 사용하지 않습니다.

## Synthetic Fixture Matrix

아래 fixture는 실제 credential이나 corpus content를 사용하지 않고 synthetic
metadata, verifier, keyring과 isolated store로 만듭니다.

| Fixture | Expected observation | Allowed disposition | Required behavior |
| --- | --- | --- | --- |
| Clean uninitialized | `CleanUninitialized` | Start | Sentinel 기반 신규 initialization만 시작 |
| Pre-source reservation-only or metadata incomplete | `InitializePreSource`; policy unobservable | Rollback-only | Sentinel/legacy provenance 주장 금지, source write 금지, exact reverse-order rollback |
| Decoded sentinel metadata complete, staged incomplete | `InitializePreSource` | Rollback-only | Source write 금지, exact reverse-order rollback |
| New sentinel staged complete | `InitializePreSource(StagedComplete)` | Resume-or-rollback | Durabilize 후 prepared 생성 또는 explicit rollback |
| New sentinel prepared | `InitializePreSource(Prepared)` | Resume-or-rollback | Sentinel source-CAS 또는 explicit rollback |
| New sentinel exact `initializing`, valid linkage/phase, temp absent/prefix/exact | `InitializeForwardOnly` | Forward-only | Derived install temp recovery와 no-replace publish |
| New sentinel exact `initializing`, valid linkage/phase, matching active key installed | `AwaitingFinalDbCas` | Forward-only | Exact source를 다시 확인한 final lifecycle CAS |
| New sentinel exact `active`, metadata retained in a valid rename/staged/prepared/metadata-removal phase | Cleanup forward phase | Forward-only | Rename 후 staged, prepared, metadata, directory 순서 cleanup |
| Legacy provenance decoded, pre-source partial | `InitializePreSource` | Rollback-only | Legacy bytes 보존, source write·rewrite 금지 |
| Legacy staged complete or prepared | `RollbackOnlyCandidate` | Rollback-only | Typed historical outcome, explicit rollback 뒤 새 init |
| Legacy exact `initializing` source with valid linkage/phase | Install/final-CAS forward phase | Forward-only | DB source를 rollback하지 않고 exact forward recovery |
| Legacy exact `active` source, metadata retained in a valid cleanup phase | Cleanup forward phase | Forward-only | Legacy provenance rewrite 없이 cleanup 완료 |
| Exact `active`, metadata retained, awaiting metadata removal | `AwaitingCleanupMetadataRemoval` | Forward-only | Retained source revalidation 뒤 metadata 삭제 |
| `active`, metadata absent, empty cleanup directory | `AwaitingCleanupDirectoryRemoval`; source `NotApplicable` | Forward-only | Lifecycle/keyring/namespace invariant로 빈 directory 제거 |
| Terminal active, transition/cleanup namespace absent | `InitializationComplete` | Idempotent cleanup replay | Active-key durability 재검증 뒤 `AlreadyCompleted`; listener readiness로 승격하지 않음 |
| Sentinel metadata with legacy DB marker, or inverse | `Blocked(InconsistentDbFilesystem)` | Operator-action, fail-closed | Evidence 보존; startup은 listener-ready 금지; automatic mutation 0 |
| Retained expectation이 있는 `initializing|active`의 noncanonical DB marker | Storage corruption | Fail-closed and poison | Source adoption·normalization 금지 |
| Invalid metadata/staged linkage or safely observed illegal filesystem combination | `Blocked` or filesystem error | Operator-action or fail-closed | Unknown artifact 자동 삭제·채택 금지 |
| Post-source inspection 중 source-shape corruption, migration drift 또는 A/B fingerprint drift | Storage/context error | Fail-closed and poison | Mutation 중단, retained evidence 보존 |
| Source-CAS response loss | Fresh committed-view classification | Forward-only, retry or explicit rollback, or fail-closed | `Initializing + Exact`만 committed, `CleanUninitialized + NotApplicable`만 no-commit, 그 외 ambiguous |
| Final-CAS response loss | Fresh committed-view classification | Forward-only, retry, or fail-closed | Expected revision/keyring guard를 만족한 `Active + Exact`만 committed, `Initializing + Exact`만 no-commit, 그 외 ambiguous |

`Rollback-only`와 `Forward-only`는 자동 동작을 뜻하지 않습니다. Exclusive maintenance
lock, retained artifact identity, source A/B observation과 command별 revalidation을 모두
통과한 explicit maintenance command만 해당 방향으로 진행합니다.

## Recovery Command Impact

### Preparation

Metadata v1 golden fixture의 신규 canonical bytes는 sentinel을 포함하도록 갱신합니다.
Legacy fixture는 별도로 유지해 decoder/readback을 검증합니다.

### Pre-source Recovery

`uses_current_blocklist` 성격의 판정은 `is_current_no_blocklist_policy`와 같은 의미로
교체합니다. Sentinel complete stage/prepared만 recovery seed를 만들고 legacy는
typed rollback-only outcome을 반환합니다.

### Pre-source Rollback

현재의 `prepared → staged-keyring → metadata → transition directory` exact-path
reverse-order protocol을 current와 legacy에 모두 유지합니다. Recovery classification이
rollback permission을 약화하거나 자동 선택하지 않습니다.

### Source-CAS And Commit Classification

New source seed는 sentinel metadata에서만 만들어집니다. DB insert, pre-commit
readback, expected CAS miss와 fresh committed-view classifier는 existing exact source
contract를 사용합니다.

### Install, Final CAS And Cleanup

Post-source에서는 sentinel과 legacy를 차별하지 않고 metadata/DB exact equality와
filesystem identity, staged linkage, active-key equality 및 phase-shape invariant를
요구합니다. Install temp recovery, atomic no-replace publish, exact final lifecycle
CAS와 deletion-only cleanup ordering을 바꾸지 않습니다.

## Rejected Alternative

Candidate 1은 이 POV-031 slice에서 거절합니다.

- Metadata v2만으로 migration `0004`의 required field를 없앨 수 없습니다.
- 후속 migration은 migration fixtures를 바꾸고 source shape, fingerprint와 CAS 분기를
  요구합니다. 새 table로 authority를 옮기면 exact auth table inventory도 바뀝니다.
- 구버전 binary가 metadata v2와 future migration을 안전하게 rollback할 수 없습니다.
- Schema cleanup과 corpus 제거를 한 변경에 묶으면 recovery regression의 원인을
  분리하기 어렵습니다.
- Candidate 2가 existing historical recovery contract로 동일한 security outcome을 더
  작은 변경 면적에서 제공합니다.

이 거절은 future schema cleanup 자체를 금지하지 않습니다. Legacy compatibility를
제거할 수 있는 배포·상태 evidence가 생기면 별도 ADR과 append-only migration에서
검토합니다.

## Consequences

장점:

- Corpus, updater, digest, version constant와 enforcement API를 current tree에서
  완전히 제거할 수 있습니다.
- Migration `0004`/`0005`, source-CAS, fingerprint와 final-CAS protocol을 보존합니다.
- Legacy pre-source는 source로 전진하지 않고 legacy post-source는 data loss 없이
  forward completion합니다.
- Retained expectation 구간의 metadata/DB mixed state와 drift를 기존 exact matcher로
  fail closed합니다.
- Sentinel pre-source를 구버전 binary가 historical로 처리하므로 application rollback
  경계가 metadata v2보다 좁고 결정적입니다.

비용:

- `blocklist_version` field와 metadata v1 slot의 잘못된 이름이 남습니다.
- Application이 sentinel exact value를 강제하며 migration `0004`의 SQL CHECK 자체는
  sentinel만 허용하지 않습니다.
- Password common/compromised defense가 줄어듭니다. 대체 corpus, online lookup 또는
  strength meter는 이 결정에 포함하지 않습니다.
- Golden metadata fixture와 current/historical synthetic fixture를 정책 용어에 맞게
  갱신해야 합니다.

## Residual Risks

- 구버전 application으로 rollback하면 그 binary의 과거 new-password enforcement가
  다시 동작할 수 있습니다. Persisted recovery compatibility와 별개의 product behavior
  risk이며 rollback review에서 명시해야 합니다.
- Terminal `InitializationComplete`는 metadata가 제거돼 source fingerprint를 더 이상
  reconciliation evidence로 요구하지 않는 좁은 protocol state입니다. Future production
  startup은 credential row의 compatibility를 별도로 검증해야 하며 이 state만으로
  listener를 열 수 없습니다.
- Stable canonical metadata/DB mismatch에 대한 자동 repair는 없습니다. Operator가
  evidence를 검토하기 전 startup wiring은 이 상태를 listener-ready로 승인하면 안
  됩니다.
- Same-UID race, abrupt process termination, power-loss durability와 filesystem별
  atomicity residual은 기존 auth transition contract에 남습니다.
- Future schema cleanup은 table rebuild/backfill, dual read, downgrade와 backup/restore
  영향을 다시 결정해야 합니다.
- POV-031 current-tree 제거만으로는 당시 Git history, clone, fork와 cache에서 과거
  material을 회수하지 못했습니다. 현재 저장소는 기존 Git graph를 반입하지 않은
  fresh-history restart로 이 상속 위험을 제거했지만, 이전 저장소의 외부 copy 부재까지
  보증하지 않습니다.

## Rollout And Rollback

1. 사용자가 sentinel semantics와 legacy disposition을 승인해 이 ADR을 Accepted로
   전환했습니다.
2. 같은 POV-031에서 corpus/updater/enforcement removal과 compatibility code/test를
   하나의 reviewable current-tree 변경으로 구현했습니다.
3. Sentinel 신규 fixture, legacy pre/post-source, mixed-state, commit-uncertainty,
   서로 다른 길이의 metadata v1 round-trip과 구버전 downgrade classification을
   검증했습니다.
4. POV-031 current-tree inventory 뒤 project-owned code에 MIT License를 적용했고,
   sanitized current tree만 새 public repository history에 반입했습니다.
5. Application rollback은 DB와 metadata를 rewrite하지 않습니다. 구버전 binary가
   sentinel pre-source를 만나면 rollback-only, exact post-source를 만나면
   forward-only로 처리하는 compatibility를 검증합니다.
6. POV-032의 destructive rewrite 절차는 repository restart로 superseded됐습니다.
   현재 저장소 운영 정책은 과거 material 복원이나 old history force-push를 rollback
   경로로 두지 않습니다.

## Approval Record

2026-07-27 사용자가 다음 항목을 명시적으로 승인했습니다.

- Candidate 2와 exact sentinel `no-blocklist-check-v1`
- sentinel이 “검사 통과”가 아니라 “corpus evaluation을 주장하지 않음”이라는 의미
- legacy pre-source 전부 rollback-only
- exact source와 기존 filesystem/phase invariant를 모두 만족하는 legacy post-source는
  forward-only
- stable typed `Blocked`의 evidence-preserving operator-action과 underlying
  filesystem/store/context error의 poison
- migration `0004`/`0005` 유지 및 이번 단계의 새 migration 없음
- 잘못 이름 붙은 field의 future cleanup을 별도 ADR/migration으로 연기
- blocklist 제거로 common/compromised password 방어가 줄어드는 residual risk

## Links

- [ADR-0004](0004-local-authentication-and-session-security-contract.md)
- [POV-007](../tickets/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-031](../deps/POV-031-remove-password-blocklist-feature.md)
- [POV-032](../deps/POV-032-purge-password-blocklist-history-and-caches.md)
- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
