# POV-007 Local Login, Refresh And Session Revoke

Status: In Progress — dependency-independent control plane, sentinel/legacy initialization recovery, source/final-CAS and deletion-only cleanup slices implemented; Windows workspace validation restored by POV-034 and POV-031 current-tree removal completed; activation gated by POV-022

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-004, POV-005, POV-022

## Why

개인 기록을 저장하거나 조회하기 전에 모든 domain command가 검증된 owner context에서 실행되어야 합니다. local 사용도 인증과 session revoke 경계를 생략할 이유가 되지 않습니다.

## What

accepted auth decision에 따라 ID/password login, 짧은 수명의 access token, rotating opaque refresh token, logout과 session revoke를 구현합니다. 보호 API는 request payload가 아니라 검증된 session subject로 owner scope를 주입합니다.

## Scope

- explicit clean-instance sentinel, listener-closed resumable signing-key/account bootstrap와 password verification
- exclusive auth maintenance lock, planned rotation, verify-only retirement, compromise/loss recovery와 crash-resumable key lifecycle
- login, refresh rotation, logout와 active session persistence
- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)의 access token verification과 owner context middleware
- auth verifier 내부에서만 production `VerifiedAuthContext` 발급; public/raw owner constructor 금지
- refresh replay detection과 related session revoke
- password change, saved recovery-code rotation/recovery와 user disable/re-enable
- local browser token/cookie profile
- auth/token redaction과 negative audit evidence

## Delivery Slices

1. Conversation DB auth control-plane migration, typed records와 commit-uncertainty용 reopenable writer
2. owner-only secret filesystem, maintenance lock, canonical keyring, initialization source-CAS와 crash-resumable key lifecycle
3. password/recovery validation, durable throttle와 controlling-TTY maintenance commands
4. strict access JWT, login/session/refresh state machine와 opaque verified-owner issuer
5. fail-closed startup, local auth HTTP/cookie boundary와 installed-browser evidence

각 slice는 listener를 우회하거나 synthetic production auth context를 만들지 않습니다. POV-022가
`proceed` 또는 compatible `narrow` 결정을 내리고 모든 slice와 conditional browser evidence가
완료되기 전에는 production activation과 ticket completion을 주장하지 않습니다.

## Out Of Scope

- public signup, password-reset email 또는 social login
- TOTP
- remote Cloudflare session profile
- shared workspace roles
- domain record mutation

## Acceptance Criteria

- unauthenticated 또는 invalid session request는 domain command 실행 전에 거부됩니다.
- owner scope는 verified subject와 active session에서만 생성되며 body/URL owner ID로 바뀌지 않습니다.
- refresh token은 사용마다 rotate되고 이전 token replay 시 결정된 session revoke policy가 적용됩니다.
- logout, password change와 user disable 이후 관련 refresh credential을 사용할 수 없습니다.
- access/refresh token이 URL, Web Storage, IndexedDB, log와 오류 응답에 나타나지 않습니다.
- local browser에서 login, refresh와 logout flow를 synthetic account로 재현할 수 있습니다.
- initialization/planned/retire/compromise/loss key transition의 모든 injected crash 뒤 listener가 mixed state에서 열리지 않고 허용된 resume/rollback으로 terminal state에 도달합니다.

## Verification

- accepted [ADR-0004 executable test matrix](../decisions/0004-local-authentication-and-session-security-contract.md#executable-test-matrix)의 local/auth-API clauses: `AUTH-JWT-*`, `AUTH-KEY-*`, `AUTH-ID-*`, `AUTH-PASS-*`, `AUTH-CLI-*`, `AUTH-TXN-*`, `AUTH-REC-*`, `AUTH-REF-*`, `AUTH-REV-*`, `AUTH-COOKIE-01/03/04`, `AUTH-CSRF-*`, `AUTH-STOR-01`, `AUTH-LOG-01`, `AUTH-CACHE-01`
- `AUTH-JWT-05` inverse, `AUTH-REF-04` remote lifetime, `AUTH-COOKIE-02/03`, remote Origin/CSRF, browser storage, log/cache 등 모든 remote-profile applicable clause는 future trusted HTTPS remote-auth delivery가 다시 검증합니다.
- `AUTH-REV-02` SSE-close와 `AUTH-CACHE-01` SSE clause 및 `AUTH-SSE-01`은 POV-011, `AUTH-CACHE-01` upload clause와 `AUTH-UP-01`은 POV-015가 다시 검증합니다.
- auth success, invalid signature/claim, expired token, replay와 revoke tests
- owner spoofing negative test
- actual repository format, check, test, build and `git diff --check`

## Implementation Evidence

- Conversation migration `0004_local_auth_control_plane.sql`은 clean store에서 exact
  `uninitialized` lifecycle sentinel 하나와 auth-owned row 0개로 시작합니다.
- Storage contract tests는 lifecycle kind/KID 전이, immutable `OR REPLACE` 거부,
  outcome-session-version linkage, terminal session cascade, profile별 marker/session cap,
  exact local refresh lifetime와 generation `0..8191` boundary를 synthetic data로 검증합니다.
- Private auth mutation executor는 captured device/inode/owner identity와 current migration
  history를 fresh private-cache writer마다 검증하고 COMMIT failure/response loss 뒤 active
  transaction rollback, explicit close와 별도 read-only committed-view classification을
  순서대로 강제합니다. Synthetic tests는 deferred-FK COMMIT failure, response loss,
  caller cancellation, worker panic, poisoned re-entry, DB path replacement, migration drift,
  dirty-read isolation, ambiguous committed view와 writer-close failure를 검증합니다.
  Commit 전 expected CAS miss는 typed success outcome으로 분리하며 store/history 재검증,
  rollback과 close 뒤 classifier 없이 반환하고 poison하지 않습니다. Synthetic tests는
  already-applied/precondition-changed outcome, migration drift rollback, classifier 미호출과
  expected-no-commit close failure poison을 검증합니다.
- Append-only migration `0005_auth_throttle_bounds.sql`은 exact durable deadline과
  admission, password count 100 terminal bound, recovery count 100 saturation/revision 갱신을
  강제합니다. Boundary, under/over-delay, integer overflow, `OR REPLACE`와 invalid legacy
  migration rollback을 synthetic DB에서 검증합니다.
- Credential primitive는 consuming/zeroizing secret type, NFC password boundary, canonical
  recovery grammar, exact current Argon2id PHC parser/hash/verify와 process-wide non-waiting
  cancellation-safe KDF slot을 제공합니다. Password corpus, caller-supplied blocklist
  context, embedded digest, updater와 enforcement API는 POV-031에서 제거됐습니다.
- Crate-private keyring codec은 Ed25519 signing seed에서 public key와 RFC 7638 `kid`를
  재계산하고 active-only 170-byte/verify-only 261-byte canonical v1 형식을 encode/decode합니다.
  RFC 8032 golden vector, 모든 truncation, appended/unknown form, checksum/semantic corruption,
  zero/weak/mismatched/duplicate key, SQLite integer/time overflow, exact 11-minute overlap와
  redacted Debug를 synthetic unit tests로 검증합니다.
- Crate-private pure transition contract는 exact `auth-keyring.v1`, five-kind
  transition/cleanup과 derived install temp의 lowercase hyphenated RFC 4122 UUID v4 basename,
  reservation의 exact `metadata`/`staged-keyring`/`prepared` 이름을 format/parse합니다.
  Initialization-only metadata v1은 maximum 512-byte versioned/checksummed binary이며 caller
  digest 대신 canonical active-only keyring v1의 actual 170 bytes에서 result KID/version/key
  activation, staged length와 SHA-256을 계산합니다. 별도 source timestamp는 key activation
  이상이어야 하고 initialization DB timestamp들의 canonical source입니다. Persisted wire
  slot은 legacy policy provenance로 취급하며 새 metadata는 exact
  `no-blocklist-check-v1` sentinel을 기록하고 recovery decode는 strict grammar의 legacy
  token을 lossless하게 보존합니다. Owned staged bytes는 length/hash,
  strict keyring decode와 version/KID/activation cross-check를 모두 통과해야 합니다.
  UUID v4 transition/owner/audit ID, exact login과 independent-salt canonical password/recovery
  PHC를 보존하며 모든 truncation, append, alternate UUID spelling/version/variant, unknown tag,
  length/checksum, timestamp regression/overflow, semantic corruption, salt reuse와 Debug/error
  disclosure를 거부합니다.
  Planned/retire/compromise/loss metadata persistence는 kind-specific source-CAS payload 계약이
  accepted될 때까지 unsupported이며 이 pure codec은 filesystem이나 DB를 변경하지 않습니다.
- Unix crate-private instance primitive는 exact `stores/`와 `secrets/` directory 및 persistent
  empty `auth-maintenance.lock`을 owner-only mode, no-follow/pinned identity와 close-on-exec로
  검증합니다. Synthetic tests는 unsafe root/child/lock artifact 무변경 거부, root
  rename/replacement split-brain 차단, non-empty lock 거부, same-process와 subprocess
  contention, holder crash release, exec-child non-inheritance와 redacted Debug를 검증합니다.
  Layout을 소비하는 locked capability는 Conversation store의 open-time DB parent identity를
  pinned `stores/` descriptor와 두 차례 대조한 뒤에만 maintenance context를 만들며, context
  revalidation과 drop까지 lock ownership을 유지합니다. Synthetic tests는 same-instance
  lifetime, cross-instance rejection, same-directory DB replacement, 같은 DB inode를 옮긴
  replacement directory rejection과 path-free error/Debug를 검증합니다.
- Crate-private maintenance actor admission은 borrowed context를 Storage가 발급한 non-Clone
  owned binding으로 전환하고, bounded mailbox와 전용 OS thread 하나가 exact store identity,
  shared poison과 lock을 함께 소유합니다. Accepted revalidation의 reply receiver/caller task
  drop과 Tokio runtime shutdown은 worker를 취소하지 않습니다. Per-command panic과 admitted
  identity drift는 content-free failure 뒤 terminal poison으로 전환합니다. Actor ownership이
  유지되는 동안 lock을 보유하고 explicit shutdown은 thread를 join하며, handle Drop은 detach하되
  이미 admitted된 current/queued command가 끝날 때까지 lock을 유지합니다. 정상 receiver
  drop과 mailbox pressure는 poison하지 않습니다. Shutdown ownership은 blocking join으로
  넘긴 뒤 waiter cancellation과 분리됩니다. Synthetic tests는 joined lifetime, dropped
  receiver, capacity bound, runtime teardown, shutdown-waiter abort, panic poison-before-unlock,
  post-admission DB replacement와 redacted Debug를 검증합니다.
- Typed read-only clean inspection은 actor의 같은 OS thread에서 held lock과 pinned layout을
  재검증하고 bounded raw-basename manifest A를 만듭니다. 인식된 top-level file과 reservation
  directory 및 그 안의 known file은 no-follow/close-on-exec descriptor로 pin하고, owner-only
  mode, regular/directory type, file link count 1, bounded size, descriptor/path identity와
  size/mtime/ctime을 확인합니다. Raw name과 file bytes는 redacted zeroizing owner로 보존하며
  같은 descriptor를 positional read해 content와 SHA-256 안정성도 확인합니다. Directory
  link count는 채택 조건이 아니라 A/B drift evidence로만 보존하고 unknown/noncanonical
  top-level/nested entry는 삭제하거나 채택하지 않는 typed `UnrecognizedPresent`입니다.
- macOS extended ACL 확인의 최소 unsafe FFI는 audited safe boundary인 `pov-platform`에
  격리합니다. Core는 retained FD를 `fstat A → exact extended-ACL absence → fstat B`로
  검사하고 root/store/secrets/lock/known/reservation artifact에서 ACL presence 또는
  조회·순회·해제 불확실성을 fail closed합니다. 이 slice는 blanket xattr 거부가 아니며
  path-only ACL 판정이 아니며 ACL evidence 자체를 lifecycle phase나 filesystem mutation의
  근거로 사용하지 않습니다.
- Manifest A와 zeroizing metadata decode를 actor thread에 유지한 채 exact bound store의
  fresh read-only/private-cache typed initialization lifecycle/source observation A를 읽고, 같은
  retained FD/content/path/manifest의 filesystem B, 별도 typed observation B equality와 final
  filesystem revalidation을 순서대로 확인합니다. Clean snapshot은
  store contract, current migration history, exact 12-table auth manifest, canonical
  `uninitialized` singleton, 나머지 auth row와 `auth_audit` sequence residue 부재를 검증합니다.
  Initializing snapshot은 account/password/recovery 각 1, 두 throttle, login-control, sole
  `auth_initialized` audit와 marker/outcome/session/family/token 0개를 요구합니다. 모든 source
  row는 같은 canonical owner, revision/version `1`, source timestamp, independent verifier salt,
  exact state/null shape여야 하며 `sqlite_sequence`는 `auth_audit`의 integer `1`만 scoped합니다.
  다른 table의 sequence row는 허용합니다.
- Read-only reconciliation result는 exact `uninitialized` filesystem을 `CleanUninitialized`와
  initialization `ReservationOnly|MetadataIncomplete|MetadataComplete|StagedIncomplete|
  StagedComplete|Prepared`로 구분합니다. Linked complete stage/prepared는 exact policy
  sentinel일 때만 `ResumeOrRollbackCandidate`이고 legacy metadata는
  `RollbackOnlyCandidate`입니다. Metadata와 exact-match하는 canonical `initializing` source,
  intact prepared reservation에서는 install-temp 부재, empty를 포함한 strict staged prefix,
  exact temp와 installed active key를 forward-only phase로 구분합니다. Exact initialization
  `active` revision `2`와 full canonical source, installed key, intact transition reservation은
  `AwaitingCleanupRename`입니다. Matching cleanup namespace는 exact contents에 따라
  `AwaitingCleanupStagedRemoval|AwaitingCleanupPreparedRemoval|AwaitingCleanupMetadataRemoval|
  AwaitingCleanupDirectoryRemoval`로만 재개합니다. Active revision `2`, keyring version `1`,
  canonical active key의 matching KID/version과 `activation <= lifecycle time`,
  lock+active-key-only namespace는 terminal `InitializationComplete`입니다. Metadata가 제거된 뒤 empty
  cleanup과 terminal replay는 metadata-backed full canonical source identity를 증명하지 않습니다.
  다른 active+temp, mismatched cleanup, unsupported lifecycle와 unknown/noncanonical artifact는
  삭제·채택하지 않고 redacted blocked result로 보존합니다.
- Canonical metadata 값 또는 lifecycle-vs-metadata mismatch는 non-poisoning blocked result이며,
  source cardinality/state/revision/time/owner/salt/audit shape 손상, typed initialization
  lifecycle/source observation A/B drift, final
  filesystem drift, unsafe artifact와 schema/identity/rollback/close uncertainty는 terminal
  poison입니다. Synthetic tests는 여섯 pre-source, install/final-lifecycle/cleanup forward phase와
  terminal state, sentinel/legacy policy recovery, empty/length-minus-one install prefix,
  exact source mismatch, unrelated SQLite sequence 허용, audit-sequence/salt corruption,
  active+temp와 illegal cleanup preservation 및 drift checkpoint를 검증합니다. 기존
  clean/lifecycle/artifact/ACL race suite도 유지됩니다.
  `Clean`과 reconciliation result는 authorization, mutation 또는 listener-readiness capability가
  아닙니다. Preparation command는 같은 actor에서 exact clean reconciliation을 다시 실행한
  뒤에만 reservation을 만들지만 그 result도 재사용 가능한 source-mutation capability가 아닙니다.
  Pre-source recovery/rollback, source-CAS, active-key install, final lifecycle과 cleanup command는
  매 호출마다 retained artifact/context와 applicable DB source를 다시 검증합니다. Metadata가
  있는 exact initialization `Active` revision
  `2`는 expectation과 full source를 검증하지만 `InitializationComplete`는 active lifecycle/key와
  exact namespace의 좁은 terminal protocol state일 뿐 auth repository validity나 listener
  readiness가 아닙니다. 그 밖의 unsupported `Active|Transitioning`은 lifecycle facts만 비교한
  뒤 Blocked하므로 그 state의 mutable auth row를 whole-DB snapshot으로 비교한다는 근거가
  아닙니다.
- Crate-private initialization preparation command는 raw password/recovery, caller path/digest/KID를
  받지 않는 `InitializationPreparationV1`만 actor mailbox로 받습니다. 이 preparation의
  construction은 zero source timestamp를 actor admission이나 artifact creation 전에 거부합니다.
  Exact clean precondition이면
  mutator가 `mkdir` 직전에 secret directory의 pinned exact lock-only namespace를 다시
  capture/revalidate합니다. 그 predicate가 그대로일 때만
  `.auth-transition-initialize-<uuidv4>` owner-only `0700` directory를 no-replace로 만들고
  parent를 fsync한 뒤 canonical `metadata`, matching `staged-keyring`, empty `prepared`를
  owner-only `0600`, no-follow, close-on-exec, exclusive-create file로 순서대로
  write/readback/fsync하고 reservation directory를 각 단계에서 fsync합니다. Final
  reconciliation이 exact sentinel `Prepared`/`ResumeOrRollbackCandidate`일 때만
  `Prepared`를 반환하며 Conversation DB lifecycle과 auth row는 `uninitialized`/empty로 유지합니다.
- Duplicate 또는 다른 non-clean state는 redacted `PreconditionNotClean` typed outcome으로
  mutation과 poison 없이 반환합니다. Outer reconciliation 뒤 recognized reservation을 주입한
  race test는 immediate pinned namespace recheck가 requested second reservation을 만들지 않고
  injected recognized artifact를 그대로 보존한 채 `ReservationOnly` typed outcome을 반환하는
  것을 검증합니다. Infrastructure/durability error는 partial artifact를 자동 삭제하지 않고
  actor와 shared Conversation operation을 poison합니다.
- Synthetic durability injection은 reservation, metadata, staged keyring, prepared sentinel의
  네 fsync/revalidation checkpoint를 각각 검증합니다. 각 failure는 DB를 exact
  `uninitialized`/auth-row-empty로 유지하고, 존재해야 하는 exact artifact bytes만 보존하며,
  actor/store를 poison하고 lock을 joined shutdown까지 유지합니다. Fresh actor readback은 각각
  `ReservationOnly`/`RollbackOnlyCandidate`, `MetadataComplete`/`RollbackOnlyCandidate`,
  `StagedComplete`/`ResumeOrRollbackCandidate`,
  `Prepared`/`ResumeOrRollbackCandidate`의 exact phase를 재현합니다. Clean-to-Prepared의 exact
  mode/bytes/readback, `InitializationPreparationV1` zero source-time 무변경 거부, duplicate
  무변경과 dropped receiver 뒤 admitted completion도 검증합니다. 실제 abrupt process
  termination과 power-loss durability는 아직 직접 harness하지 않았습니다.
- Crate-private no-payload initialization pre-source recovery command는 same lock-owning actor에서
  exact `uninitialized` DB와 policy sentinel `StagedComplete|Prepared`의
  `ResumeOrRollbackCandidate`만 채택합니다. Retained metadata와 staged keyring을 file 및
  reservation-directory fsync 뒤 재검증하고, `StagedComplete`이면 empty owner-only `prepared`를
  no-follow exclusive-create/readback/fsync하며 `Prepared`이면 기존 sentinel을 rewrite 없이
  durabilize합니다. Final exact `Prepared` reconciliation 뒤
  `Prepared|AlreadyPrepared|NotRecoverable`을 redacted typed outcome으로 반환합니다.
- Legacy/partial/clean/post-source/blocked/cleanup state는 mutation-free `NotRecoverable`이고
  explicit rollback 선택을 자동으로 대신하지 않습니다. Synthetic tests는 staged recovery,
  prepared replay, recovery 뒤 source-CAS와 rollback, legacy/ineligible no-mutation,
  metadata/staged/prepared durability fault와 fresh-actor resume, source race, reservation inode
  ABA, hard-link, post-create drift, redaction과 dropped receiver 뒤 admitted completion을
  검증합니다. Mutation 또는 durability uncertainty 뒤에는 evidence를 보존하고 actor/store를
  poison하며, 실제 abrupt process termination, power-loss와 마지막 검사 직후 malicious
  same-UID ABA는 residual입니다.
- Crate-private no-payload initialization pre-source rollback command는 exact clean
  `uninitialized` DB A/B와 legal initialize transition만 같은 lock-owning actor에서
  채택합니다. Cleanup namespace를 만들거나 caller path/ID/phase를 deletion target으로 받지
  않고 retained typed artifact에서 exact name을 derive합니다. Sentinel/legacy policy의
  여섯 pre-source phase를 모두 명시적으로 rollback할 수 있지만 sentinel
  `StagedComplete|Prepared`의 recovery 선택을 자동으로 대신하지 않습니다.
- Rollback은 creation 역순인 `prepared → staged-keyring → metadata → transition directory`로
  exact retained FD/path/content/link/ACL을 검사해 unlink하고 각 containing directory를
  fsync합니다. Command 시작 때 검증한 transition ID, reservation directory identity와 original
  known-file FD/content를 terminal readback까지 보존하고, 각 fresh snapshot이 같은 reservation의
  predicted subset인지 대조합니다. 따라서 crash checkpoint가 `Prepared → StagedComplete → MetadataComplete →
  ReservationOnly → CleanUninitialized`의 기존 legal phase에 남습니다.
  `StagedIncomplete`는 staged 제거 뒤 `MetadataComplete`, `MetadataIncomplete`는 metadata
  제거 뒤 `ReservationOnly`로 수렴합니다. 매 삭제 뒤 fresh reconciliation이 바로 앞
  mutation이 예측한 exact next phase와 같은지 확인하고 DB lifecycle/auth row/audit/sequence,
  active key와 cleanup namespace를 바꾸지 않습니다.
- Typed redacted outcome은 `RolledBack|AlreadyClean|NotRollbackable`입니다. `AlreadyClean`은
  tombstone이 없는 현재-state 결과이지 same-command completion 증거가 아닙니다. Stable
  clean replay와 blocked/post-source state는 mutation 없이 store를 건강하게 유지하고, 첫
  mutation 뒤 phase drift, filesystem/DB/context 또는 durability uncertainty는 remaining
  evidence를 보존한 채 actor/store를 poison합니다.
- Synthetic rollback tests는 여섯 sentinel phase, legacy
  `MetadataComplete|StagedIncomplete|StagedComplete|Prepared`, exact
  clean replay, confirmed-no-commit rollback, preexisting cleanup namespace와
  post-source/unknown-artifact 무변경 거부,
  prepared/staged/metadata/directory fault 뒤 exact fresh-actor phase와 resume, pre-mutation
  source-CAS drift, same-phase reservation inode ABA, hard-link insertion, post-removal DB drift,
  outcome redaction과 dropped receiver 뒤 admitted completion을 검증합니다. 정상 success,
  deletion-checkpoint fault와 confirmed-no-commit 경로는 Conversation DB를 exact
  `uninitialized`, auth row/audit/sequence residue 0으로 유지합니다. Drift cases는 주입된 DB나
  filesystem evidence를 되돌리지 않고 그대로 보존하면서 actor/store를 poison합니다. 실제 abrupt process
  termination, power-loss/filesystem durability, 마지막 검사 직후 malicious same-UID ABA와
  unlink의 physical secure erase는 conditional residual입니다.
- Crate-private no-payload initialization source command는 exact maintenance lock과 bound store를
  소유한 전용 actor OS thread에서 동기적으로 실행됩니다. Retained secret snapshot과 zeroizing
  metadata를 유지한 채 typed DB observation A/B, retained filesystem과 context를 확인하고,
  exact sentinel `Prepared`/`ResumeOrRollbackCandidate`에서만 metadata가 소유한
  canonical seed로 Conversation DB source-CAS를 호출합니다. Writer 전에 metadata, staged
  keyring과 prepared sentinel을 각각 file 및 reservation-directory fsync하고 exact retained
  identity/content와 `Prepared` phase를 다시 검증합니다. Writer 직전과 반환 직후에도 같은
  retained artifact 및 root/store/secrets/lock/DB context를 재검증합니다. Post-source
  `InitializeForwardOnly` replay는 writer 없이 `AlreadyCommitted`, legacy pre-source
  `Prepared`/`RollbackOnlyCandidate`는 writer 없이 `LegacyPrepared`, 그 밖의 phase는
  redacted `NotPrepared`입니다. Infrastructure, retained-artifact/context drift 또는 storage
  ambiguity는 evidence를 자동 정리하지 않고 shared store와 actor를 poison합니다.
- Initialization source-CAS는 one `BEGIN IMMEDIATE`에서 exact empty `uninitialized` predicate를
  `initializing` revision/version `1`로 바꾸고 account, password/recovery credential, 두 throttle,
  login-control과 sole `auth_initialized` audit를 metadata의 owner/source timestamp/revision,
  independent PHC와 KID/transition/keyring facts로 함께 생성합니다. Commit 전에 full canonical
  source를 재검증합니다. Exact CAS miss는 같은 transaction에서 `AlreadyCommitted` 또는
  `PreconditionChanged`로 분류하고 revalidation/rollback/close 뒤 committed-view classifier 없이
  반환합니다. COMMIT response loss나 failure는 writer를 rollback/quiesce/close한 뒤 별도 fresh
  read-only private-cache view에서 full clean precondition 또는 full canonical initialized source를
  판정해 `Committed` 또는 `ConfirmedNotCommitted`로 닫습니다. 모든 typed outcome과 error는
  login, KID, PHC, digest와 source fingerprint를 Debug/error에 노출하지 않습니다.
- Synthetic actor/storage tests는 new commit 뒤 exact `AwaitingInstallTemp`, same-command replay와
  historical post-source replay의 `AlreadyCommitted`, same-source CAS race의 한 audit/sequence,
  different-source race의 `PreconditionChanged`, historical/not-prepared no-mutation, post-commit
  response loss의 `Committed`, deferred-FK COMMIT failure의 `ConfirmedNotCommitted`와 successful
  retry를 검증합니다. Metadata/staged/prepared 각 durability fence fault는 DB writer 진입 전에
  exact `uninitialized` state와 `Prepared` evidence를 보존하고 actor/store를 poison하며 fresh
  actor retry가 정상 commit하는 것도 검증합니다. Dropped receiver가 admitted mutation을
  취소하지 않는 것과 post-mutation filesystem drift가 evidence와 lock을 joined shutdown까지
  보존하면서 actor/store를 poison하는 것도 검증합니다. 마지막 immediate revalidation 뒤
  same-UID ABA와 실제 process crash/power-loss는 여전히 residual입니다.
- Crate-private no-payload initialization active-key install command는 같은 lock-owning actor OS
  thread에서 exact canonical current 또는 historical post-source와 intact staged evidence가
  만드는 forward-only phase만 전진시킵니다. Install temp가 없으면 derived basename에 owner-only
  exclusive file을 create/write/readback하고 file과 secrets directory를 fsync합니다. Strict
  staged prefix이면 retained descriptor/path/bytes가 exact할 때만 temp를 unlink하고 directory를
  fsync한 뒤 새 exact file을 만들며, exact temp이면 identity/bytes를 다시 검증하고 기존 file과
  directory를 durabilize합니다. Publish 직전 typed DB A/B, retained filesystem과 context를 다시
  검증한 뒤 install temp를 atomic `NOREPLACE` rename으로 `auth-keyring.v1`에 publish하고 secrets
  directory를 fsync합니다. Destination이 경합으로 생기면 덮어쓰지 않고 evidence를 보존합니다.
  Installed active replay는 inode를 교체하거나 source/audit를 중복 기록하지 않고 exact file과
  directory를 다시 durabilize하며 `AlreadyAwaitingFinalDbCas`를 반환합니다. Active key 설치 뒤에도
  lifecycle은 final DB CAS 전까지 `initializing`이고 reservation/staged/prepared evidence를
  보존합니다.
- Synthetic active-key install tests는 absent temp의 exact publish와 replay, empty/strict-prefix
  delete-create recovery, exact-temp reuse, historical canonical source forward install, pre-source
  no-mutation, non-prefix typed blocker, prefix removal/install-temp fsync/publish fsync의 세 durability
  checkpoint, raced destination `NOREPLACE`, post-install active drift poison과 dropped receiver 뒤
  admitted completion을 검증합니다. 이 fault injection은 phase별 recoverable evidence를 확인하지만
  실제 abrupt process termination이나 power-loss durability를 직접 재현하지 않으며 마지막
  immediate revalidation 뒤 same-UID ABA도 여전히 residual입니다.
- Crate-private no-payload initialization final lifecycle command는 exact installed active key와
  intact reservation/metadata/staged/prepared, full canonical current 또는 historical initialization
  source를 같은 lock-owning actor에서 다시 검증한 뒤에만 storage CAS를 호출합니다. One
  `BEGIN IMMEDIATE`에서 exact `initializing` state revision `1`, transition ID, expected KID,
  keyring version과 source timestamp를 compare-and-set하고 lifecycle만 `active` revision `2`로
  바꾸며 transition kind/ID를 `NULL`로 만듭니다. Expected KID와 keyring version은 보존하고
  metadata의 기존 `source_at_micros`를 lifecycle `updated_at_micros`로 계속 사용하므로 final
  activation을 위한 새 clock을 도입하지 않습니다. Account/credential/throttle/login-control,
  sole audit와 key file은 다시 쓰지 않습니다.
- Final lifecycle 성공은 original reservation/staged/prepared evidence를 삭제하지 않고 exact
  `AwaitingCleanupRename` phase와 `ActivatedAwaitingCleanup`을 반환합니다. Exact active replay는
  file inode, source와 audit를 다시 쓰지 않고 durabilize/revalidate한 뒤
  `AlreadyActivatedAwaitingCleanup`으로 수렴합니다. Confirmed no-commit은 intact
  `AwaitingFinalDbCas`와 `ConfirmedNotActivated`로 남고, 다른 phase는 redacted
  `NotActivatable` 또는 drift error로 닫습니다. COMMIT uncertainty는 rollback/quiesce/close한
  writer와 fresh non-shared committed view로 exact active 또는 prior initializing
  postcondition만 분류합니다.
- Synthetic storage/actor tests는 exact active revision `2`와 null transition fields, preserved
  KID/version/source timestamp, reservation과 active inode 보존, exact replay, historical canonical
  source, COMMIT response loss, deferred-FK confirmed no-commit와 retry, exact external writer race,
  different-source/pre-install no-mutation, post-commit filesystem drift poison과 dropped receiver
  completion을 검증합니다.
- Crate-private no-payload initialization cleanup command는 exact `AwaitingCleanupRename`, active
  revision `2`/keyring version `1`, canonical active key, full current 또는 historical source와
  intact transition reservation을 같은 lock-owning actor에서 다시 검증합니다. Verified
  transition ID에서 derived한 `.auth-cleanup-initialize-<uuidv4>`로 directory 전체를 atomic
  no-replace rename하고 secret parent를 fsync합니다. Initialization cleanup은 install temp가
  absent일 때만 admit되며 이를 cleanup 대상으로 채택하거나 삭제하지 않습니다.
- Rename 뒤 cleanup namespace는 deletion-only입니다. Exact staged keyring, prepared sentinel,
  metadata, empty cleanup directory를 그 순서로 exact-path 제거하고 각 containing directory를
  fsync하며 `AwaitingCleanupStagedRemoval → AwaitingCleanupPreparedRemoval →
  AwaitingCleanupMetadataRemoval → AwaitingCleanupDirectoryRemoval → InitializationComplete`로
  전진합니다. DB lifecycle/source/audit와 canonical active key file/inode는 바꾸지 않습니다.
  성공과 exact terminal replay는 redacted `Completed|AlreadyCompleted`로 수렴하고 non-cleanable
  state는 `NotCleanable`입니다.
- Synthetic cleanup tests는 exact rename과 replay, staged/prepared/metadata/directory별 durability
  failure 뒤 deletion-only resume, historical source, raced cleanup destination no-replace,
  source/filesystem pre-mutation drift, post-mutation drift poison과 dropped receiver completion을
  검증합니다. Unknown/noncanonical/illegal partial cleanup은 자동 삭제하지 않고 manual fail
  closed합니다. 이 fault injection은 실제 abrupt process termination, power-loss 또는
  filesystem별 atomicity/durability를 직접 재현하지 않습니다. Cooperative lock과 retained
  FD/path/manifest revalidation도 rename/unlink 직전 또는 final postcheck 직후 malicious same-UID
  ABA를 원자적으로 배제하거나 이미 끝난 namespace mutation을 되돌리지 않습니다. Unlink는
  copy-on-write, journal 또는 snapshot에서 physical secure erase를 보장하지 않습니다.
- 이 evidence는 schema, storage, credential primitive, pure in-memory keyring/initialization-transition codec와
  unwired instance/maintenance-lock/store-binding/detached-actor/read-only initialization reconciliation 및
  initialization-only pre-source durable preparation·recovery·exact rollback,
  exact `Prepared → initializing` source-CAS와 pre-writer durability fence,
  active-key install, final `initializing → active` lifecycle CAS와 deletion-only cleanup primitive
  slice에 한정됩니다. `InitializationComplete`와 cleanup `Completed|AlreadyCompleted`는 metadata가
  제거된 뒤 active revision/KID/version/key/namespace만 확인하는 protocol terminal이며 full
  mutable auth source, auth validity 또는 listener readiness 증명이 아닙니다. Actor에는
  planned/retire/compromise/loss transition command가 없으며 production auth
  mutation repository, listener,
  dummy verifier/account selection, JWT, refresh mutation, controlling-TTY flow, reference-device
  Argon2 benchmark, local HTTP와 production instance-root/runtime wiring, preparation/source
  predicate 직후 same-UID ABA의 원자적 차단, process crash/power-loss state-machine과
  installed-browser clauses는 아직 PASS가 아닙니다.

## Cross-platform Verification Baseline

[POV-034](../deps/POV-034-restore-windows-workspace-validation-baseline.md)는
`storage/auth_records.rs`, 이를 소비하는 storage binding/type과 crate-private transition
re-export를 같은 Unix gate로 정렬했습니다. Windows는 migration `0004`/`0005`와 canonical
auth schema를 계속 적용하지만 Unix auth maintenance capability를 compile하거나 stub으로
제공하지 않습니다. Windows workspace와 Unix auth synthetic suite가 모두 통과했으며,
이는 POV-007 production activation이나 미구현 auth slice의 완료 증거가 아닙니다.

## Rollback

신규 login을 닫고 active session을 revoke할 수 있어야 합니다. 이미 생성된 account와 audit record는 migration 없이 삭제하지 않습니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-004](../deps/POV-004-core-data-identity-and-store-boundaries.md)
- [POV-005](../deps/POV-005-authentication-and-session-security-decision.md)
- [POV-034](../deps/POV-034-restore-windows-workspace-validation-baseline.md)
- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)
- [POV-022](POV-022-first-segment-and-voice-wedge-discovery-gate.md)
