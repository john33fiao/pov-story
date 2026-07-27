# ADR-0004: Local Authentication And Session Security Contract

- Status: Accepted
- Date: 2026-07-25
- Decision ticket: [POV-005](../deps/POV-005-authentication-and-session-security-decision.md)
- Partial supersession:
  [ADR-0005](0005-password-blocklist-removal-and-legacy-auth-compatibility.md)
  (Accepted 2026-07-27; password blocklist enforcement와 persisted marker semantics만)

ADR-0005는 offline/caller-supplied password blocklist enforcement,
compiled blocklist version의 current-marker 의미와 `AUTH-PASS-02`의
blocked-candidate/list-update clause만 부분 supersede합니다. Password grammar,
Argon2id, zeroization, KDF admission, throttle, recovery, key lifecycle, transaction,
JWT/session/cookie/CSRF/redaction 계약은 이 ADR대로 유지됩니다.

## Context And Threat Boundary

POV Story는 한 owner의 민감한 개인 기록을 다루지만, 현재 `pov-api`에는 account, credential, session, token issuer 또는 auth middleware가 없습니다. 구현 전에 password, JWT, refresh, browser cookie, revoke와 recovery 계약을 하나로 고정하지 않으면 각 endpoint가 서로 다른 owner 근거와 failure behavior를 만들 수 있습니다.

현재 보호 경계는 single-owner app instance, owner가 통제하는 OS account와 app-owned data root입니다. local profile은 인터넷 없이 `http://127.0.0.1:8080`에서 동작해야 합니다. remote profile은 향후 exact HTTPS origin과 Cloudflare Tunnel evidence가 있을 때만 활성화할 수 있습니다. 같은 OS account로 임의 process와 app data를 읽을 수 있는 공격자, browser/OS 자체 compromise, phishing과 XSS 완전 방어는 현재 경계 밖입니다.

이 결정은 password-only 인증을 NIST AAL 적합 구현으로 주장하지 않습니다. 특히 local HTTP에는 authenticated protected channel과 `Secure` cookie가 없고, cookie는 port별로 격리되지 않습니다. 이 예외는 loopback profile에만 허용합니다.

## Decision

### Identity Authority And Persistence

- account, password/recovery verifier, throttle, login-attempt admission marker/outcome, session, active refresh family/predecessor와 auth audit source는 네 source boundary를 늘리지 않고 Conversation DB의 control-plane auth namespace에 둡니다. Embedding DB나 browser는 auth source가 아닙니다.
- signing private key는 DB와 환경변수 밖의 app-owned secret directory에 둡니다. 이 directory와 file은 Unix에서 각각 `0700`, `0600`, no-follow, atomic replace 규칙을 따릅니다.
- bootstrap에서 owner가 정하는 login identifier는 exact ASCII `login_id` 하나이며 3~32 bytes, regex `[a-z][a-z0-9_-]{2,31}`를 만족해야 합니다. 이 release에서는 immutable이고 internal UUID `owner_id`와 분리합니다. Login input은 JSON string을 decode한 뒤 byte-for-byte 비교하며 trim, Unicode normalization, case-fold, alternate separator 또는 alias를 허용하지 않습니다. Grammar 밖 input은 account lookup이나 Argon2 없이 같은 mutation-free invalid-request response로 거부하고, well-formed unknown ID만 known ID와 같은 dummy verifier/throttle 경로를 사용합니다.
- 보호 요청은 access JWT의 signature와 모든 claim을 검증한 뒤 active account, active `sid`, matching owner와 credential version을 server source에서 확인해야 합니다. 이 검증을 모두 통과한 auth verifier만 production `VerifiedAuthContext`를 만들 수 있습니다.
- request body, URL, model output, cookie의 owner 값이나 검증된 `sub` 하나만으로 owner scope를 만들지 않습니다. session owner와 token `sub`가 다르면 fail closed합니다.
- `pov-api`는 아직 이 issuer/verifier나 auth schema를 구현하지 않았습니다. 이 ADR의 local-auth subset은 POV-007, SSE/upload subset은 후속 ticket, remote subset은 trusted ingress decision 뒤 delivery의 구현 계약입니다.

### Password, Throttling And Recovery

[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#passwords)의 길이, blocklist, arbitrary composition·periodic change 금지와 [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)의 memory-constrained Argon2id profile을 적용합니다.

- password verifier는 `Argon2id v=19, m=65536 KiB, t=3, p=4`, CSPRNG 16-byte unique salt, 32-byte output을 사용하고 PHC string에 version과 parameters를 보존합니다.
- 대상 장비 benchmark는 POV-007에서 수행합니다. 이 release는 위 exact PHC profile만 생성·검증하며 arbitrary per-record 또는 weaker/stronger legacy parameter를 받지 않습니다. Active credential의 malformed/unsupported PHC는 listener startup 전에 fail closed합니다. Parameter 변경은 known/unknown dummy-work equivalence, mixed-version migration과 rollback evidence를 포함한 superseding ADR이 필요하고, 어떤 경우에도 [OWASP minimum](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-hashing-algorithms)을 밑돌지 않습니다.
- H0에는 독립적으로 보호되는 secret store가 없으므로 pepper를 사용하지 않습니다.
- 입력은 normalization 전 최대 1024 UTF-8 bytes이고 유효한 UTF-8이어야 합니다. NFC normalization 뒤 15~128 Unicode code point를 허용하며 NUL은 거부합니다. space와 Unicode를 허용하고 trim, truncate, case-fold, 문자 종류 조합 또는 정기 변경을 강제하지 않습니다.
- 이 bullet의 versioned offline blocklist와 caller-supplied context enforcement는
  [ADR-0005](0005-password-blocklist-removal-and-legacy-auth-compatibility.md)가
  부분 supersede했습니다. Current tree는 corpus evaluation을 주장하지 않는 exact
  sentinel을 compatibility wire slot에 기록하며 corpus, network lookup 또는 strength
  meter로 새 password를 거부하지 않습니다.
- single-owner instance의 login, password change와 recovery-code rotation을 포함한 모든 current-password 검증은 하나의 durable password-authenticator throttle counter를 공유합니다. Login의 known account, unknown ID와 wrong password는 같은 counter와 public response를 사용합니다. 허용된 login attempt에서는 실제 verifier 또는 같은 parameter의 Argon2 dummy verifier를 실행합니다. Throttle 중에는 어떤 password path도 같은 generic `429`를 받고 verifier를 실행하지 않으며 account 존재 여부나 남은 delay를 응답하지 않습니다.
- admitted Argon2 password verification이 실제로 실패한 경우에만 이 instance-wide counter와 next-allowed time을 갱신합니다. throttle 또는 busy 때문에 거부한 generic `429`는 counter를 바꾸지 않습니다. 5번째 admitted failure부터 `min(30 seconds × 2^(failures-5), 1 hour)` backoff를 적용하고 어떤 admitted password path든 successful verification이면 reset합니다. Durable failure transition과 recovery-counter reset은 이전 next-allowed deadline 이상에서만 가능하고 새 failure deadline은 updated time과 이 exact backoff로 계산한 값이어야 합니다. 100번째 연속 admitted failure는 password authenticator를 disable하고 recovery를 요구합니다. unknown-ID flood도 충분한 시간 동안 허용된 failure를 누적하면 owner를 recovery로 밀어낼 수 있는 availability risk를 명시적으로 수용합니다. Schema password-counter reset은 admitted successful password verifier와 deadline 전 recovery-authorized password reset을 구분할 수 없으므로, typed auth mutation repository가 observed verifier/account/throttle state CAS와 authorization을 함께 강제합니다.
- password/recovery Argon2 verification은 process 전체에서 하나만 실행합니다. 이미 실행 중이면 login, current-password와 recovery-code attempt 모두 같은 mutation-free generic `429`를 반환합니다. Admitted recovery-code failure는 password counter와 분리된 durable counter에 같은 backoff를 적용하며 successful recovery-code verification만 그 counter를 reset합니다. Recovery counter는 100에서 포화되고 recovery authenticator를 영구 disable하지 않습니다. 100 이후에도 throttle을 통과한 admitted failure마다 failure count는 100을 유지한 채 새 1시간 deadline과 throttle revision을 갱신합니다.
- saved recovery code는 OS CSPRNG 16 bytes를 base64url-no-pad canonical 22-character payload로 encoding한 exact ASCII `povrec1_<payload>` 30 bytes입니다. Input은 이 grammar로 decode한 값이 exactly 16 bytes이고 re-encode가 원문과 같을 때만 허용하며 trim, case-fold, Unicode normalization 또는 alternate separator를 적용하지 않습니다. Verifier는 password와 같은 exact `Argon2id v=19, m=65536 KiB, t=3, p=4`, independent unique 16-byte salt, 32-byte output PHC string이며 blocklist 대상이 아닙니다. Recovery dummy verifier도 같은 profile을 사용하고 malformed/unsupported stored recovery PHC는 listener startup 전에 fail closed합니다.
- bootstrap은 이 saved recovery code 하나를 user-controlled terminal에 한 번 표시하고 사용자가 보관을 명시적으로 확인한 뒤에만 signing-key initialization reservation을 만들거나 account를 commit합니다. 확인 전 output loss/crash에는 durable auth state를 만들지 않습니다. source, transition reservation, config, log 또는 repository에는 raw code를 저장하지 않습니다.
- recovery는 loopback-only local operator command에서 recovery code와 새 password를 함께 요구합니다. Old code 검증 뒤 replacement code를 먼저 표시하고 사용자가 보관을 확인한 경우에만 성공 Conversation DB transaction이 old code consume, replacement hash, password hash와 credential version 변경, 모든 session revoke, login/recovery throttle reset과 password authenticator re-enable을 함께 commit합니다. Commit 실패에는 old code가 계속 유효하고 자동 login하지 않습니다. administratively disabled account는 별도 explicit re-enable 전까지 disabled 상태를 유지합니다.
- recovery code를 잃었지만 signing key와 enabled password authenticator가 유효하면 loopback-only operator command에서 current password를 재검증하고 같은 pre-commit display/confirmation 절차로 code를 rotate하며 모든 session을 revoke합니다. Successful current-password verification은 shared password counter를 reset하지만 이 preventive rotation은 recovery throttle을 reset하거나 disabled password authenticator를 re-enable하지 않습니다. Password와 saved code를 모두 잃었거나 signing key와 saved code를 모두 잃으면 지원되는 bypass/reset 경로가 없습니다.
- password change는 현재 password 재검증, user disable/re-enable과 key-loss recovery는 recovery code를 요구합니다. email, SMS, security question, support override와 browser password-reset endpoint는 제공하지 않습니다.
- Local operator command는 password와 recovery code를 argv, environment variable, command-line option value 또는 redirected stdin으로 받지 않습니다. Controlling TTY가 아니면 secret input을 거부하고, terminal echo를 끈 interactive prompt에서 읽은 뒤 success, error, signal 모든 exit path에서 echo를 복원합니다. Replacement recovery code의 one-time terminal display만 의도된 raw-secret output입니다. Automated tests는 CLI가 아니라 in-memory library seam에 synthetic secret을 주입합니다.

### Auth Mutation Commit Boundaries

- Login request는 authorization 근거가 아닌 client-generated UUID v4 `login_attempt_id`를 profile과 함께 사용합니다. Browser는 profile별 password-login request를 하나만 in-flight로 두고 겹쳐 보내지 않습니다. Prior fetch가 terminal success/failure/abort가 되기 전에는 transport retry나 refresh probe를 시작하지 않으며, terminal uncertainty 뒤 같은 ID를 memory로 재사용합니다. Each admitted ID creates an immutable profile-scoped admission marker with a fixed one-hour expiry plus an optional credential-version-bound success/failure outcome payload. Existing failure payload는 original generic failure를 verifier/counter mutation 없이 재현하고, existing committed-session payload는 session이나 cookie를 replace/reissue하지 않은 `409 login_outcome_unknown` no-store body를 반환합니다. Marker는 있지만 credential change가 payload를 무효화했거나 payload가 unavailable이면 verifier/counter mutation 없이 generic `409 login_attempt_invalidated`를 반환하고 client는 새 ID를 사용합니다. Client는 outcome-unknown response가 겹친 original보다 먼저 온 경우 original settlement를 기다리고, original fetch가 이미 terminal이면 cookie가 도착했을 가능성을 refresh로 probe합니다. Cookie가 없거나 terminal일 때만 새 attempt ID로 명시적으로 login합니다.
- New attempt는 profile의 non-expired admission marker가 64개 미만일 때만 verifier admission을 받을 수 있습니다. Marker와 optional outcome payload는 creation부터 fixed one-hour uncertainty window를 가지며 refresh, retry, logout-all, recovery 또는 credential-version change가 marker expiry를 연장하거나 marker를 삭제하지 않습니다. Transaction은 expired marker/payload를 먼저 prune하고 still-full이면 모든 새 ID에 mutation-free generic `429`를 반환합니다. 따라서 cap exhaustion은 clock rollback이 없는 한 최대 한 시간 뒤 자동 해제되고, credential mutation이나 operator recovery로 우회되지 않습니다. Admitted password failure transaction도 verifier가 관찰한 account 존재/identifier, password hash 또는 dummy selection, throttle/admission-set version, credential version과 marker absence를 compare합니다. 모두 같을 때만 marker, shared throttle update/disable과 failure payload를 함께 commit합니다. Concurrent password/recovery/account/logout-all mutation으로 하나라도 달라졌으면 counter, marker 또는 outcome을 쓰지 않고 mutation-free generic retry-required response로 끝내며 client는 새 attempt ID를 사용합니다.
- Successful new attempt는 candidate `sid`, raw refresh, digest, access JWT와 response bytes를 memory에서 먼저 생성·sign·serialize하되 emit하지 않습니다. Password verification에서 관찰한 account, password hash, throttle/admission-set version, credential version과 marker absence를 Conversation DB source transaction 안에서 다시 compare한 뒤 admission marker, password-throttle reset, active session, 최초 refresh digest와 success payload를 함께 commit합니다. Concurrent duplicate 중 하나만 marker/outcome을 만들고 loser는 authoritative outcome을 read해 같은 failure 또는 outcome-unknown response를 냅니다. 각 profile은 active login session을 최대 8개만 허용하고 새 성공이 cap을 넘으면 oldest session/family를 같은 transaction에서 terminal-delete합니다. One-hour outcome expiry 뒤에도 orphan session은 이 independent eight-session cap에 의해 bounded됩니다.
- Logout endpoint는 bearer가 이미 invalid/revoked여도 exact profile Host/Origin/custom-header 검사를 먼저 통과한 refresh cookie를 DB에서 조회합니다. Current session/family terminal deletion을 commit하거나 cookie digest가 absent/unknown/already terminal임을 정상 DB read로 확인한 뒤에만 matching clear-cookie와 generic response를 반환합니다. 따라서 terminal commit 뒤 response가 유실돼도 stale cookie retry가 state를 되살리지 않고 clear할 수 있습니다. DB unavailable/conflict에는 clear-cookie나 success를 내지 않습니다. Logout-all은 credential version 증가, unexpired admission marker 보존과 outcome payload invalidation, 모든 session/family terminal deletion을 한 source transaction에 commit한 뒤 같은 idempotent clear behavior를 사용합니다.
- Password change, recovery-code rotation과 user disable/re-enable은 각각 password/recovery verifier의 observed version을 다시 비교하고 credential/account mutation, credential version 증가, 모든 session/family terminal deletion, unexpired admission marker 보존, retained outcome payload invalidation과 applicable password/recovery-counter reset을 한 source transaction에 commit합니다. Recovery와 key compromise/loss도 앞 절과 key lifecycle에 정의한 replacement verifier, throttle reset, marker preservation, outcome-payload invalidation과 terminal deletion을 같은 source transaction에 포함합니다. 모든 outcome payload는 생성 당시 credential version에 묶여 current version과 다르면 invalid이며, version-changing transaction 뒤 stale success/failure를 재현하지 않습니다. Admission marker는 credential version과 독립적이고 fixed expiry까지 cap에 포함됩니다.
- 이 mutation transaction이 commit 전 conflict/failure이거나 authoritative readback이 no-commit을 확인하면 source state와 revoke/version은 모두 이전 상태이고 candidate access/refresh, issue/clear cookie 또는 success response를 내지 않습니다. Replacement recovery code를 미리 표시한 operation은 old verifier가 계속 유효하며 표시한 replacement는 무효라고 알리고, 재시도에서는 새 code를 다시 표시·확인합니다.
- [SQLite transaction semantics](https://www.sqlite.org/lang_transaction.html#implicit_versus_explicit_transactions)상 failed `COMMIT`은 transaction을 active로 남길 수 있으므로 commit error/uncertainty 뒤 writer connection의 SELECT를 committed evidence로 사용하지 않습니다. 모든 statement를 finalize/reset하고 transaction이 남아 있으면 `ROLLBACK`한 뒤 writer handle을 close·abandon해 later commit이 불가능함을 확인합니다. 그 다음 shared-cache가 아닌 fresh Conversation DB connection에서 exact operation postcondition을 읽어 committed/no-commit을 판정합니다. Writer quiescence나 fresh committed-view를 증명하지 못하면 process는 token, cookie, success를 emit하지 않고 listener를 fail closed합니다.

### Access JWT

[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3)의 algorithm pinning, key/algorithm binding, claim validation과 explicit typing에 따라 다음 exact profile만 허용합니다.

- JWS `alg=EdDSA`, curve Ed25519만 허용합니다. `none`, HMAC, RSA, ECDSA, unknown algorithm과 token-provided key URL/JWK는 모두 거부합니다.
- protected header는 exact `typ=pov-access+jwt`와 현재 keyring에 존재하는 `kid`를 요구합니다. [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)의 Ed25519 public key를 `kty=OKP`, `crv=Ed25519`, 32-byte public key의 base64url-no-pad `x`로 표현하고, [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)의 lexicographic required-member JSON인 `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` UTF-8 bytes를 SHA-256한 base64url-no-pad value를 `kid`로 사용합니다. Optional JWK member는 thumbprint input에서 제외합니다.
- required claims는 exact `iss=urn:pov-story:auth`, request profile에 따라 exact `aud=urn:pov-story:api:local` 또는 `aud=urn:pov-story:api:remote`, canonical OwnerId `sub`, UUID v4 `sid`, UUID v4 `jti`, positive integer credential version `ver`, `iat`, `nbf=iat`, `exp=iat+600 seconds`입니다.
- duplicate, missing, wrong-type 또는 unknown critical header를 거부합니다. serialized token은 최대 4096 bytes이며 `exp-iat`가 600초를 넘으면 거부합니다.
- access lifetime은 local/remote 모두 10분입니다. verifier clock skew는 최대 30초이며 future `iat`/`nbf`와 expired `exp` 양쪽에만 적용합니다.
- 모든 보호 HTTP request는 exact Host에서 request profile을 먼저 결정한 뒤 matching audience, active account/session/version과 session profile을 확인합니다. local token/session은 remote API에, remote token/session은 local API에 사용할 수 없습니다. long-lived SSE는 각 event 전과 최대 15초 heartbeat마다 다시 확인하고 `exp`, revoke, disable 중 먼저 발생한 시점부터 15초 안에 닫습니다.

### Signing-Key Lifecycle

- OS CSPRNG로 Ed25519 key를 생성하며 active signing key는 하나입니다. planned cryptoperiod는 90일이고, 기한이 지난 key는 다음 maintenance startup에서 rotate합니다.
- Conversation auth schema migration은 singleton lifecycle row를 `uninitialized`, `expected_kid=NULL`, `transition_id=NULL`로 만듭니다. 이 state, auth-owned account/credential/throttle/session/refresh/audit row 0개, keyring/transition-or-cleanup reservation/install-temp artifact 0개가 모두 맞을 때만 clean instance입니다. Persistent empty lock file은 이 predicate에서 제외합니다. Schema 적용 뒤 lifecycle row가 없거나 이 조합이 어긋나면 corruption으로 거부합니다. 기존 app data root 전체가 명시적으로 제거되어 새 Conversation store가 만들어진 경우는 새 instance이며 삭제된 이전 auth/data의 복구로 간주하지 않습니다.
- owner가 local terminal에서 명시적으로 실행한 `auth init`만 clean instance를 초기화할 수 있습니다. command는 exclusive maintenance process에서 API/auth listener를 열지 않고 password를 검증한 뒤 key, owner/account ID, password/recovery verifier를 준비합니다. 앞 절의 recovery code display와 보관 확인이 끝난 뒤에만 durable initialization을 시작합니다. 다른 auth row, expected key, keyring, transition/cleanup reservation 또는 install-temp artifact가 이미 있으면 init은 덮어쓰거나 정리하지 않고 거부합니다. Cleanup namespace는 matching active DB/key postcondition에서만 삭제할 수 있고 `uninitialized` state에서는 fail closed합니다.
- API/auth startup과 모든 auth maintenance command는 state를 읽기 전에 secret directory의 고정 owner-only, no-follow lock file을 `O_CLOEXEC` 또는 platform-equivalent close-on-exec로 열고 같은 nonblocking OS exclusive file lock을 획득합니다. Startup은 auth listener lifetime, maintenance는 preflight부터 reservation cleanup까지 lock을 보유합니다. Lock fd는 provider/media child에 상속하지 않습니다. Lock을 얻지 못하면 listener와 mutation을 시작하지 않습니다. Process crash는 kernel lock을 해제하며 persistent empty lock file은 clean predicate에서 제외합니다. Unsafe permission/symlink lock file은 fail closed합니다.
- key file과 Conversation DB는 하나의 transaction으로 묶지 않습니다. Initialization, planned rotation, verify-only key retirement, compromise와 loss-recovery는 listener를 열지 않은 maintenance mode와 owner-only transition reservation을 사용해 idempotent하게 resume합니다.
- Active keyring의 exact secret-directory basename은 `auth-keyring.v1`입니다. Top-level auth artifact grammar는 persistent `auth-maintenance.lock`, active `auth-keyring.v1`, `.auth-transition-<kind>-<id>`, `.auth-cleanup-<kind>-<id>`, `.auth-keyring-install-<id>.tmp`만 허용합니다. `<kind>`는 exact lowercase `initialize|planned|retire|compromise|loss`, `<id>`는 lowercase 36-byte hyphenated RFC 4122 UUID v4만 허용하며 uppercase, simple/braced/URN form, 다른 version/variant, suffix, separator, NUL과 non-UTF-8 name을 alias로 받지 않습니다. Reservation/cleanup directory 안의 이름은 exact `metadata`, `staged-keyring`, content-free `prepared`만 허용합니다. 동시에 transition 또는 cleanup namespace 하나만 존재할 수 있고 install temp ID, directory kind/ID, metadata kind/ID와 DB transition bytes가 모두 일치해야 합니다. Unknown/mismatched artifact는 자동 채택·rename·삭제하지 않고 fail closed합니다.
- 모든 transition은 먼저 secret directory 아래에 `.auth-transition-<kind>-<id>` owner-only directory를 no-follow, no-replace `mkdir`로 만들고 parent directory를 fsync합니다. Atomic directory name이 incident kind와 unique transition ID를 보존하므로 process가 그 직후 crash해도 incident kind를 구분할 수 있습니다.
- Initialization metadata v1만 현재 persistence codec으로 고정합니다. Exact wire order는 `POVAUTHM` 8-byte magic, big-endian `format_version:u16=1`, checksum을 포함한 `total_length:u32`, `kind_tag:u8=1`, raw 16-byte UUID v4 transition ID, raw 16-byte UUID v4 owner ID, raw 16-byte UUID v4 auth-audit ID, canonical 43-byte result active `kid`, `result_keyring_version:u64=1`, `key_activated_at_micros:u64`, `source_at_micros:u64`, `staged_keyring_length:u32=170`, actual staged bytes에서 계산한 raw 32-byte SHA-256, `login_length:u8`와 exact login bytes, `password_phc_length:u16`와 canonical current PHC bytes, `recovery_phc_length:u16`와 independent-salt canonical current PHC bytes, `blocklist_version_length:u8`와 version bytes, 마지막 앞선 전체 bytes의 raw 32-byte SHA-256입니다. 전체 길이는 최대 512 bytes입니다. 두 시각은 SQLite signed-integer 범위이고 DB source/reservation 시각인 `source_at_micros`는 staged key activation보다 빠를 수 없으므로 `source_at_micros >= key_activated_at_micros`를 강제합니다. Initialization source CAS에서 `source_at_micros`는 `auth_key_lifecycle.updated_at_micros`, account/password/recovery의 `created_at_micros`와 `updated_at_micros`, 두 initial throttle의 `updated_at_micros`, `auth_login_control.clock_floor_micros`/`created_at_micros`/`updated_at_micros`, `auth_audit.happened_at_micros`에 동일하게 매핑합니다. Canonical seed는 lifecycle `initializing` revision/version `1`, enabled account/password credential과 recovery credential revision `1`, account/credential version `1`, password/recovery throttle `failure_count=0`, `next_allowed_at_micros=0`, revision `1`, login-control admission/control revision `1`, marker/outcome/session/family/token row `0`, `auth_initialized` audit row와 `audit_sequence=1`을 정확히 하나씩 가집니다. `sqlite_sequence` 검사는 `name=auth_audit`, integer `seq=1`에만 scoped하며 다른 table의 sequence row는 이 postcondition과 무관합니다. Audit의 `profile/session_id/attempt_id`는 `NULL`입니다. Login은 기존 exact 3~32-byte grammar, persisted blocklist version은 1~64-byte lowercase ASCII로 첫 byte가 `[a-z]`, 마지막 byte가 `[a-z0-9]`, 중간이 `[a-z0-9-]`여야 합니다.
- Result KID/version/key activation/staged length/hash는 caller가 보내는 값이나 digest가 아니라 codec이 canonical active-only keyring v1의 actual encoded bytes에서 가져옵니다. 새 initialization metadata encoder는 caller가 blocklist version을 선택하게 하지 않고 binary에 compile된 exact `BLOCKLIST_VERSION`을 캡처합니다. Recovery decoder는 과거에 이 grammar로 기록된 canonical version token을 보존해 읽을 수 있지만 새 metadata로 바꾸지 않습니다. DB가 아직 exact `uninitialized`인 pre-source recovery에서 metadata version이 current compiled version과 다르면 source CAS로 진행하지 않고 initialization reservation을 허용된 exact rollback/cleanup한 뒤 current password policy, recovery-code display와 confirmation부터 다시 시작합니다. Exact metadata version과 verifier를 포함한 `initializing|active` source postcondition이 이미 commit된 post-source recovery는 historical token을 current value로 rewrite하거나 key를 rollback하지 않고 forward completion합니다. Durable stage 승인 시 actual owned secret bytes의 exact length/SHA-256을 확인한 뒤 canonical keyring v1으로 strict decode하고 active-only/version/KID/key activation을 metadata와 다시 대조해야 하며 hash-only match는 승인이 아닙니다. Encoded metadata와 verifier의 secret buffer는 drop 때 zeroize하고 aggregate `Debug`/error에 field 값을 노출하지 않습니다.
- Initialization `metadata`는 위 owner ID, exact immutable `login_id`, password/recovery verifier, blocklist version과 audit ID를 기록합니다. Schema에는 별도 account UUID가 없으므로 기존 “owner/account UUID”는 이 singleton account의 `owner_id` 하나를 뜻합니다. Tags for planned/retire/compromise/loss are reserved but unsupported by metadata v1: their exact observed credential/recovery revision and postcondition payload contract is accepted and implemented before any such reservation is persisted. `retire`의 result active KID는 old active KID와 같고 keyring version만 증가하므로 모든 kind에 “new KID”가 있다고 가정하지 않습니다. Raw password와 raw recovery code는 metadata에 쓰지 않습니다. `metadata`를 owner-only no-follow `O_CREAT|O_EXCL`로 write/fsync하고 reservation directory를 fsync한 뒤에만 exact `staged-keyring` file을 만들 수 있습니다.
- `staged-keyring`을 owner-only no-follow `O_CREAT|O_EXCL`로 완전히 write/validate/fsync하고 reservation directory를 fsync합니다. 그 뒤 content 없는 `prepared` sentinel을 `O_CREAT|O_EXCL`로 만들고 file/directory를 fsync합니다. Crash 뒤 valid metadata와 matching durable stage가 있는데 sentinel이 없거나 durability가 불명확하면 둘을 재검증·fsync한 뒤 sentinel을 create/fsync할 수 있습니다. Matching metadata, stage와 prepared sentinel이 모두 있어야 source DB를 변경합니다.
- Crash가 reservation `mkdir` 뒤 metadata 완료 전에 발생하면 protocol상 stage와 source mutation은 없습니다. Exclusive lock 아래 expected-old DB/key state와 reservation contents를 확인한 뒤 incomplete metadata를 exact-path cleanup하고 directory를 fsync할 수 있습니다. Initialization/planned/retire는 reservation 전체를 제거하고 parent를 fsync해 rollback할 수 있지만 compromise/loss는 kind directory를 보존하고 listener를 닫은 채 owner-authorized retry만 metadata를 재작성할 수 있습니다. Initialization pre-source rollback은 cleanup namespace로 rename하지 않고 exact transition directory 안에서만 동작합니다. `uninitialized` lifecycle과 cleanup namespace 조합은 계속 fail closed합니다.
- Crash가 stage write/fsync 중 발생하면 source DB는 아직 expected-old state입니다. Retry는 reservation이 지목한 exact `staged-keyring`과 `prepared`만 제거하고 reservation directory를 fsync합니다. Initialization rollback은 creation 역순인 `prepared → staged-keyring → metadata → transition directory`로 exact-path unlink와 containing-directory fsync를 수행해 각 crash checkpoint를 `Prepared → StagedComplete → MetadataComplete → ReservationOnly → CleanUninitialized`의 legal phase에 남깁니다. `StagedIncomplete`는 staged 제거 뒤 `MetadataComplete`, `MetadataIncomplete`는 metadata 제거 뒤 `ReservationOnly`로 수렴합니다. Current `StagedComplete|Prepared`의 resume와 explicit rollback은 서로 다른 explicit maintenance action이며 관찰된 `ResumeOrRollbackCandidate`가 어느 쪽도 자동 선택하지 않습니다. Planned/retire는 같은 durable cleanup으로 rollback할 수 있습니다. Compromise/loss는 kind directory를 제거하지 않고, 필요한 replacement code를 다시 표시·확인한 뒤 incomplete metadata/stage를 exact-path cleanup·directory-fsync하고 같은 reservation 안에서 새 metadata와 stage를 만듭니다. 이전에 표시한 replacement code는 무효입니다.
- Initialization source transaction은 preflight에서 확인한 `uninitialized`, `expected_kid=NULL`, `transition_id=NULL` DB row와 auth-owned row 0개를 compare-and-set하면서 metadata와 exact-match하는 owner/account UUID, immutable `login_id`, credential/throttle을 만들고 `state=initializing`, matching transition ID와 expected new `kid`를 commit합니다. Non-initialization source transaction은 exact `active` lifecycle, old `kid`와 credential/recovery version을 compare하고 `state=transitioning`, matching transition ID와 expected new active `kid`를 commit합니다. Compromise/loss이면 같은 transaction에서 credential version 증가와 all-session revoke를 포함하고, loss recovery는 old recovery hash consume, confirmed replacement hash와 recovery-throttle reset도 저장합니다.
- Source transaction error 또는 commit outcome uncertainty에는 exclusive lock과 intact prepared reservation을 유지합니다. Writer의 statement와 transaction을 rollback/close·abandon해 later commit을 불가능하게 한 뒤에만 shared-cache가 아닌 fresh Conversation DB connection에서 lifecycle/auth postcondition을 읽습니다. Matching `initializing|transitioning`, transition ID, new `kid`와 required credential/revoke mutation이면 commit된 것으로 보고 forward-only resume하며 initialization은 metadata의 owner/account UUID, exact `login_id`와 verifier postcondition도 모두 일치해야 합니다. Exact expected-old state와 관련 mutation 0개이면 no-commit입니다. Initialization은 reservation을 exact-clean/parent-fsync해 rollback하고 새 code로 다시 시작합니다. Planned/retire는 prepared transition을 retry하거나 rollback할 수 있고 compromise는 incident directory를 유지한 owner-authorized retry만 허용합니다. Loss는 incident directory를 유지하면서 prepared/stage/metadata를 exact-clean/fsync하고 fresh replacement code display/confirmation부터 다시 준비합니다. Writer quiescence를 증명하지 못하거나 다른 DB/reservation 조합이면 evidence를 보존하고 fail closed합니다.
- Dependency-independent reconciliation inspection은 이 recovery 계약의 no-mutation observation subset입니다. Exclusive lock 아래 retained filesystem snapshot A와 zeroizing metadata decode를 유지한 채 typed initialization lifecycle/source observation A, filesystem B, 별도 typed observation B equality와 final filesystem revalidation을 순서대로 확인합니다. Exact `uninitialized`에서는 `ReservationOnly`, `MetadataIncomplete`, `MetadataComplete`, `StagedIncomplete`, `StagedComplete`, `Prepared`를 pre-source로 구분하고 current blocklist의 linked complete stage/prepared만 resume-or-rollback candidate이며 historical blocklist는 rollback-only candidate입니다. Exact canonical initialization source와 intact prepared transition reservation에서는 missing install temp, strict staged prefix, exact temp, installed active key와 final active lifecycle을 forward-only phase로 관찰합니다. Exact initialization `active` revision `2`는 metadata expectation과 full canonical source, installed key와 intact transition reservation이 모두 일치할 때만 `AwaitingCleanupRename`입니다. Atomic rename 뒤 matching cleanup namespace는 deletion-only `AwaitingCleanupStagedRemoval`, `AwaitingCleanupPreparedRemoval`, `AwaitingCleanupMetadataRemoval`, `AwaitingCleanupDirectoryRemoval`로만 관찰합니다. Metadata 삭제 뒤 exact active revision `2`/keyring version `1`, matching canonical active-key KID/version과 `activation <= lifecycle time`, lock+active-key-only namespace는 `InitializationComplete`이지만 full canonical initialization-source identity나 listener readiness를 증명하지 않습니다. 그 밖의 unsupported `Active|Transitioning`은 lifecycle facts만 비교한 뒤 block합니다. Canonical metadata 값 또는 lifecycle 대조 불일치는 evidence-preserving blocked result이고 seed cardinality/state/revision/time/owner/salt/audit shape 손상이나 typed observation drift/close uncertainty는 infrastructure error와 shared poison입니다. Unsupported state의 mutable auth row를 whole-DB snapshot으로 비교하지 않습니다. 이 결과는 rollback/resume 실행 권한, DB/filesystem mutation, auth validity, listener readiness 또는 마지막 revalidation 직후 same-UID 변경의 원자적 차단이 아닙니다.
- Durable source postcondition 뒤에는 source state를 rollback하지 않습니다. Durable `staged-keyring`은 그대로 보존한 채 verified transition ID에서 app이 `.auth-keyring-install-<uuidv4>.tmp` exact basename을 derive합니다. Separator, alternate name 또는 metadata-provided path를 받지 않고 verified secret directory 안에서만 owner-only no-follow `O_CREAT|O_EXCL`로 exact bytes를 copy/validate/fsync한 뒤 directory를 fsync합니다. Crash 뒤 derived temp가 이미 있으면 owner/mode/type/link-count를 재검증하고 staged bytes와 exact match하면 fsync 후 reuse합니다. Staged bytes의 strict short prefix인 interrupted temp만 exact-delete하고 directory-fsync한 뒤 recreate하며, 다른 content는 fail closed합니다. Initialization은 active path 부재가 precondition이므로 temp를 `auth-keyring.v1`에 atomic no-replace publish하고 destination이 경합해 나타나면 덮어쓰지 않고 fail closed합니다. 기존 active를 바꾸는 later non-initialization transition의 atomic replacement는 해당 kind-specific source/postcondition 구현에서 별도로 검증합니다. Secret directory를 다시 fsync한 다음 initialization final CAS는 exact installed active, intact reservation/staged/prepared와 full canonical current 또는 historical source를 재검증하고 one `BEGIN IMMEDIATE`에서 lifecycle만 `initializing` revision `1`에서 `active` revision `2`로 바꾸며 `transition_kind`와 `transition_id`를 `NULL`로 commit합니다. Expected KID와 keyring version은 그대로 보존합니다. Metadata의 기존 `source_at_micros`를 lifecycle `updated_at_micros`로 계속 사용하며 completion 시각이라는 새 clock을 도입하지 않습니다. 이 final CAS의 commit error/uncertainty도 writer를 rollback/close·abandon한 뒤 fresh non-shared connection만 사용해 판정합니다. Exact `active` postcondition이면 original reservation/staged/prepared evidence를 그대로 둔 `AwaitingCleanupRename`으로 전진하고, exact prior `initializing`이면 intact reservation/install evidence로 CAS를 재시도하며, 다른 state는 fail closed합니다.
- DB/key postcondition이 맞고 original `.auth-transition-<kind>-<id>` contents가 intact한 것을 확인한 뒤, contents를 삭제하기 전에 directory 전체를 no-replace `.auth-cleanup-<kind>-<id>`로 atomic rename하고 secret parent directory를 fsync합니다. 그 뒤에만 derived active-temp residue, staged key, prepared/metadata와 cleanup directory를 exact-path로 제거하고 containing directory를 fsync합니다. Crash 전후 old transition name 또는 cleanup name 중 하나만 남으며, cleanup name은 kind와 관계없이 deletion-only입니다. Lifecycle이 아직 `initializing|transitioning`인데 필요한 reservation/staged/installed material이 없거나 DB/key/transition이 맞지 않거나, lifecycle `active`인데 old transition directory가 partial이면 manual fail closed합니다. Lifecycle `active`와 matching installed key에 cleanup directory가 남은 경우에만 remaining residue를 제거·fsync해 terminal state를 완성합니다.
- Lifecycle state가 `active`가 아니거나 transition/cleanup reservation이 있거나 DB expected `kid`와 active keyring이 다르면 startup은 auth listener를 열지 않습니다. Protocol 중 recoverable mixed state는 허용하지만 어느 normal crash point에서도 reservation namespace로 forward resume, cleanup 또는 허용된 pre-source rollback을 결정할 수 있어야 하며, partial state에서 refresh/login을 허용하거나 terminal mixed state를 남기지 않습니다. Reservation 밖 markerless staged/install-temp material은 tamper/legacy corruption으로 자동 채택·삭제하지 않습니다.
- planned transition 완료 뒤 sign은 즉시 새 key로만 수행하고 이전 private key는 삭제합니다. 이전 public key만 11분 동안 verify-only로 보존한 뒤 같은 resumable 절차로 제거합니다.
- Source transition 전 planned/retire rollback은 기존 key를 유지합니다. 이전 private key를 재활성화하는 cryptographic rollback은 허용하지 않습니다. Uncompromised 새 key와 keyring을 읽는 application rollback은 허용합니다.
- compromise transition은 이전 key의 verify overlap 없이 public/private material을 폐기하고 all-session revoke를 source transaction에 포함합니다.
- `active` lifecycle의 기존 keyring이 missing, corrupt, unsafe permission, symlink 또는 unsupported version이면 startup은 key loss로 fail closed하고 새 key를 조용히 생성하거나 `auth init`으로 덮어쓰지 않습니다. Recovery code를 검증한 local operator command는 새 key와 replacement recovery code를 준비해 사용자가 새 code를 확인한 뒤 위 resumable transition을 수행합니다. Source transaction 전에는 기존 recovery code가 유효하고, commit 뒤에는 reservation과 staged key로 code 재입력 없이 completion만 재개합니다.
- private key, raw recovery code와 token은 backup/export policy가 별도로 accepted되기 전 일반 export 대상이 아닙니다.

### Refresh And Session Lifecycle

[RFC 9700 section 4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2)는 OAuth public client에 refresh token을 발급하는 authorization server가 sender constraint 또는 rotation으로 replay를 탐지하도록 요구합니다. POV Story는 OAuth conformance를 주장하지 않지만 같은 browser threat에 이 rotation pattern을 적용하기로 결정합니다. 현재 client는 sender-constrained key를 가지지 않으므로 strict rotation을 선택합니다.

- refresh token은 OS CSPRNG 32-byte opaque value를 base64url-no-pad로 전달합니다. server는 `SHA-256(raw token)` digest, `family_id`, `session_id`, generation과 predecessor/descendant 상태만 저장합니다. Initial token은 generation 0이고 한 family가 발급할 수 있는 generation은 exact `0..8191`, 총 8,192개입니다.
- 매 refresh는 account/session/profile/idle/absolute 상태를 확인하고 한 Conversation DB transaction에서 old digest를 consumed 처리한 뒤 new digest를 insert합니다. Current generation이 8191이면 generation 8192 child를 만들지 않고 family/session과 모든 per-token rows를 terminal-delete한 뒤 ordinary re-login-required failure와 exact clear-cookie를 냅니다. commit 전에는 access token이나 `Set-Cookie` 성공 응답을 내지 않습니다.
- active family에 속한 consumed digest의 재사용과 같은 token의 concurrent refresh는 replay입니다. 해당 family와 session 전체를 즉시 terminal-delete하며 다른 independent login session은 유지합니다. Replay, exhaustion, logout, eviction, expiry 또는 다른 all-session revoke가 family를 terminal로 만들면 같은 source transaction에서 session/family와 모든 per-token digest row를 제거합니다. 이후 old opaque token은 mapping 없는 invalid credential로 거부하며, healthy DB가 active mapping 부재를 확인한 뒤 exact cookie를 idempotently clear합니다. Missing `sid`도 access verification에서 revoked와 동일하게 거부됩니다. Active family만 predecessor digests를 보존하므로 profile별 8-session cap 아래 token rows는 최대 `8 × 8192 = 65,536`이고 terminal refresh/session rows는 0입니다.
- Auth startup은 listener를 열기 전에, 그리고 every new-session login admission과 refresh admission은 candidate mutation 전에 같은 Conversation source transaction에서 `idle_deadline <= now` 또는 `absolute_deadline <= now`인 family와 모든 per-token/session rows를 delete합니다. 이 cleanup commit이 실패하면 listener/admission은 fail closed합니다. 따라서 time-expired dormant family가 active-session/token-row budget 밖에 남거나 restart 뒤 expired row가 누적되지 않습니다.
- client는 tab 간 refresh를 single-flight로 직렬화합니다. grace period는 두지 않습니다. successful response가 유실된 뒤 old token을 재사용하면 fail closed revoke와 re-login이 발생합니다.
- local profile session은 7일 idle, 최초 login부터 30일 absolute lifetime입니다. remote profile은 12시간 idle, 7일 absolute lifetime입니다. successful refresh만 idle timestamp를 이동시키며 absolute deadline은 연장하지 않습니다.
- cookie expiry는 `min(now + profile idle lifetime, absolute deadline)`입니다. server clock과 stored deadline이 권위이며 browser expiry만 신뢰하지 않습니다.
- logout은 current session/family와 cookie를 revoke합니다. logout-all, password change, successful recovery, user disable과 signing-key compromise/loss recovery는 owner의 모든 session을 revoke하고 credential version을 증가시킵니다.
- revoke 뒤 새 request와 upload chunk/finalize는 거부합니다. revoke 전에 인증을 마친 bounded request나 upload chunk 하나는 완료될 수 있지만 finalize와 다음 chunk는 다시 검증합니다.

### Browser Profiles, CSRF And Origin

Cookie가 port를 구분하지 않는다는 [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html)의 ambient-authority 경계를 수용하되 local과 remote credential을 분리합니다.

| Property | Local loopback HTTP | Remote HTTPS |
| --- | --- | --- |
| Allowed target/origin | exact `http://127.0.0.1:8080` | one configured canonical `https://host` |
| Cookie name | `pov_refresh_local` | `__Host-pov_refresh` |
| `Secure` | absent | required |
| `HttpOnly` | required | required |
| `SameSite` | `Strict` | `Strict` |
| `Path` | `/api/auth` | `/` |
| `Domain` | absent, host-only | absent |
| Session idle/absolute | 7 days / 30 days | 12 hours / 7 days |

- remote origin은 startup config로 명시하며 설정되지 않으면 remote auth profile은 비활성입니다. local과 remote cookie name, access audience, session profile과 refresh family를 섞지 않습니다.
- profile은 exact, single `Host`와 request target으로 선택합니다. `Forwarded`, `X-Forwarded-*`, arbitrary request body 또는 model output으로 profile을 전환하지 않습니다. remote ingress에서 trusted edge context를 검증하는 별도 evidence 전에는 remote profile을 활성화하지 않습니다.
- logout/expiry는 issue 때와 같은 name, Path, Secure, HttpOnly, SameSite와 host-only scope에 `Max-Age=0`을 사용합니다.
- login, refresh, logout과 browser account mutation은 POST와 `application/json`만 허용합니다. exact `Origin`, exact `Host`, `X-POV-CSRF: 1`을 요구하고 `Origin` missing/`null`/mismatch를 거부합니다. `Sec-Fetch-Site`가 있으면 `same-origin`만 허용합니다.
- auth/API에 permissive CORS를 열지 않고 credentialed cross-origin request를 허용하지 않습니다. state-changing GET, simple form fallback과 access-token cookie fallback은 없습니다.
- exact Origin + non-simple custom header + disabled CORS가 browser CSRF proof이므로 별도 synchronizer secret은 추가하지 않습니다. `SameSite=Strict`와 Fetch Metadata는 defense in depth입니다. 이 선택은 [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)를 따릅니다.

### Browser Storage, Streaming, Cache And Redaction

- access JWT는 browser memory에만 두고 REST, SSE와 upload에 `Authorization: Bearer` header로 보냅니다. cookie, URL/query/fragment, local/sessionStorage, IndexedDB, Cache API, service worker state와 persisted client log에 저장하지 않습니다.
- refresh token은 profile의 HttpOnly cookie에만 둡니다. 일반 API, SSE와 upload는 refresh cookie를 credential로 사용하지 않고 bearer access token과 active session을 다시 검증합니다.
- native EventSource 대신 fetch streaming SSE를 사용합니다. token은 URL에 넣지 않고 `credentials: omit`을 사용하며 expiry 전에 close, single-flight refresh 뒤 last durable cursor로 reconnect합니다.
- auth, API, SSE와 upload response는 `Cache-Control: no-store`; auth/token response는 `Pragma: no-cache`와 `Referrer-Policy: no-referrer`도 보냅니다.
- logging은 allowlisted structured field만 사용합니다. password/recovery code, `Authorization`, `Cookie`, `Set-Cookie`, raw JWT/refresh/CSRF value, upload body와 malformed credential을 application/proxy/audit/panic output에서 기록하거나 반사하지 않습니다. [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude)의 exclusion 원칙을 적용합니다.
- `401`, `403`, `429`, `500`은 account/session/token 존재 여부나 claim detail을 노출하지 않습니다.

## Executable Test Matrix

아래 ID는 POV-007, POV-011 SSE, POV-015 upload와 future trusted HTTPS remote-auth delivery가 담당할 automated test name prefix입니다. fake clock, deterministic synthetic key/account/token과 isolated temporary data root를 사용하며 실제 credential이나 개인 데이터를 사용하지 않습니다.

| ID | Case | Required evidence |
| --- | --- | --- |
| AUTH-JWT-01 | `none`, HS/RS/ES, wrong Ed25519 key, unknown `kid` | 모두 generic `401 invalid_token`, domain command 0 |
| AUTH-JWT-02 | missing/wrong/duplicate `typ`, `iss`, `aud`, `sub`, `sid`, `jti`, `ver`, `iat`, `nbf`, `exp` | parser/verifier fail closed |
| AUTH-JWT-03 | future/expired token과 ±30초 skew boundary | fake clock으로 exact accept/reject |
| AUTH-JWT-04 | valid JWT + missing/revoked session, disabled account, stale version, owner mismatch | `VerifiedAuthContext` 미발급, body owner 무시 |
| AUTH-JWT-05 | local audience/session on remote Host and inverse | cross-profile bearer/session 모두 거부 |
| AUTH-KEY-00 | clean init, concurrent init/listener, child exec + parent exit, lock-holder crash, pre-confirm output loss, login-ID metadata/resume, all pre-source/exact-source reconciliation phases, scoped/unrelated `sqlite_sequence`, reservation/DB/install/cleanup crash와 invalid first-run mixtures | one CLOEXEC lock holder; child cannot retain lock; explicit sentinel only; exact immutable login ID survives resume; all phases are redacted/deterministic; structural corruption poisons while canonical mismatch blocks without mutation; staged key retained through active; no listener/terminal mixed state |
| AUTH-KEY-01 | planned rotation | 새 key sign, old/new verify overlap, 11분 뒤 old reject |
| AUTH-KEY-02 | compromise, missing/corrupt/unsafe keyring | no overlap 또는 startup fail closed, recovery 시 all-session revoke |
| AUTH-KEY-03 | reservation/partial stage, source/final-CAS COMMIT error with writer tx still active and same-handle dirty post-state, unknown commit, historical exact source, DB/filesystem observation drift, install-temp variants, replace, transition-to-cleanup rename와 partial cleanup | writer rollback/close/abandon first; fresh non-shared committed-view only; exact historical source remains forward-only; retained artifacts survive drift/failure; kind/staged material survive; derived paths only; deterministic resume/fail closed |
| AUTH-ID-01 | 2/3/32/33-byte ID, first/alphabet/separator, upper-case, whitespace, Unicode, alias, bootstrap crash/resume와 well-formed unknown | exact immutable ASCII grammar; metadata/source/readback preserve same ID; malformed is pre-verifier invalid request; unknown uses dummy/shared throttle; owner UUID remains separate |
| AUTH-PASS-01 | 15/128 code point, Unicode/space/NFC, NUL, invalid UTF-8, raw/normalized over-limit | no trim/truncate; exact boundary behavior |
| AUTH-PASS-02 | salts/exact PHC params와 unsupported stored parameter; blocklist-specific cases는 ADR-0005로 superseded | unique/current hash; unsupported PHC blocks listener |
| AUTH-PASS-03 | alternating unknown ID, wrong login and wrong current-password on change/code-rotation, concurrent attempt | one shared password counter; dummy login Argon2; rejected `429` mutation-free |
| AUTH-PASS-04 | random-ID/current-password failures, 5th through one-hour cap, restart, any password success, 100th failure | durable fake-clock backoff/reset/disable and accepted recovery DoS |
| AUTH-CLI-01 | secret-bearing argv/env/redirected stdin, non-TTY, prompt success/error/catchable signal | forbidden ingress rejected before mutation; non-echo TTY and echo restoration; only intended replacement-code display |
| AUTH-TXN-01 | success/failure response loss, forbidden client overlap, A/B duplicate arrival orders, credential mutation between verifier and failure commit, marker-with-invalidated-payload retry, one-hour expiry, 8-session and 64-marker cap/restart/exhaustion, COMMIT error with active writer tx | success never reissues inside window; stale failure writes nothing; marker/outcome once; invalidated marker never re-verifies; cap self-recovers; fresh authoritative readback |
| AUTH-TXN-02 | repeated login→logout-all/recovery/version-change cycles, logout response loss/retry; password change/code rotation/disable/re-enable race, conflict or DB failure | credential mutation invalidates payload but preserves fixed-expiry marker/cap; session/family terminal-delete atomic; unavailable/conflict has no partial state, success or clear |
| AUTH-REC-00 | recovery payload length/alphabet/canonical last bits/prefix/case/whitespace/Unicode, salt and PHC params | exact 16-byte canonical decode/re-encode; no normalization; independent salt/current PHC; malformed stored verifier blocks listener |
| AUTH-REC-01 | bootstrap/recovery/code-rotation display, confirmation, output loss와 DB failure | no pre-confirm commit; bootstrap activates; recovery resets both/re-enables/revokes; rotation resets password counter, replaces code, versions and revokes; intended TTY 외 raw code absent |
| AUTH-REC-02 | key-loss recovery at every transition phase | replacement code/hash transition, no listener during recoverable mixed state, no terminal mixed state |
| AUTH-REF-01 | one successful refresh | old consumed + new inserted in one transaction; absolute deadline unchanged |
| AUTH-REF-02 | sequential and concurrent old-token reuse, attacker-first/client-first | one success at most, then family/session revoked |
| AUTH-REF-03 | lost refresh/replay response and stale-cookie retry | old retry revokes and requires re-login; terminal retry idempotently clears exact cookie; no grace |
| AUTH-REF-04 | local/remote idle and absolute boundaries | fake clock rejects exact expired boundary; rotation cannot extend absolute |
| AUTH-REF-05 | generations 8190/8191, attempted 8192 child, idle/absolute fake-clock crossing, restart/startup prune, replay/eviction/logout terminal deletion와 repeated stale token | no generation 8192; atomic terminal delete + re-login; active token rows <=65,536/profile; terminal rows 0; expired family prunes; stale opaque tokens and missing sid remain rejected/cleared |
| AUTH-REF-06 | DB transaction failure | no access token, cookie or partial rotation state |
| AUTH-REV-01 | logout vs logout-all | current session only vs all owner sessions denied immediately |
| AUTH-REV-02 | password change, recovery, disable, key compromise | all access/refresh denied; existing SSE closes within 15 seconds |
| AUTH-COOKIE-01 | local issue/send/clear, logout response loss and terminal retry | exact local attributes on `127.0.0.1:8080`; refresh/logout succeeds; stale cookie is idempotently cleared |
| AUTH-COOKIE-02 | remote issue/send/clear and HTTP downgrade | exact `__Host-` attributes over synthetic HTTPS; no HTTP send |
| AUTH-COOKIE-03 | opposite-profile, duplicate and malformed cookie | fail closed without credential reflection |
| AUTH-COOKIE-04 | local same host, different port | cookie is observable by second loopback port; residual remains explicit |
| AUTH-CSRF-01 | missing/null/wrong Origin or Host, missing custom header, cross-site Fetch Metadata | mutation 0 |
| AUTH-CSRF-02 | form, text/plain, state-changing GET, preflight, permissive CORS | all denied; no ACAO/ACAC opt-in |
| AUTH-STOR-01 | login/refresh/reload/logout with unique token canaries | access memory-only; refresh not script-readable; no auth/token material in Web Storage, IndexedDB, Cache or service-worker state |
| AUTH-LOG-01 | unique canary in every credential/header/body/error path | canary count 0 across app/proxy/audit/panic output |
| AUTH-CACHE-01 | auth/API/SSE/upload no-store responses and service worker | required no-store headers; those responses and auth canaries absent from Cache API |
| AUTH-SSE-01 | connect, expiry, refresh, cursor resume, revoke | header bearer only, URL clean, no-store, exact reconnect/no owner leak |
| AUTH-UP-01 | expiry/revoke between chunk and finalize, retry after refresh | current bounded chunk rule, later calls denied, no duplicate object/job |

### Reproducible Browser Probe

`node scripts/auth-cookie-probe.mjs`는 listener를 `127.0.0.1`에만 bind하되 exact navigation Host를 production origin과 cookie scope가 다른 `localhost:18080|18081`로 강제합니다. Production name과 다른 `pov_cookie_probe_local` canary만 issue/clear하고 unexpected Host는 `421`, `pov_refresh_local` 또는 `__Host-pov_refresh`가 있는 request는 mutation 없이 `409`로 거부합니다. Production strings는 cookie를 설정하지 않는 `X-POV-Set-Cookie-Specimen` header로만 보여주므로 기존 auth cookie를 덮어쓰거나 삭제하지 않습니다.

1. disposable target-browser state에서 exact `http://localhost:18080/`을 열고 `/probe/local/set`에서 probe-only local cookie를 issue합니다.
2. primary `/api/auth/echo`가 `local-cookie-present=true`인지 확인합니다.
3. `http://localhost:18081/api/auth/echo`도 `true`인지 확인해 cookie가 port-isolated가 아님을 negative evidence로 남깁니다.
4. `/probe/user-agent`의 exact browser string과 실행 날짜를 evidence에 기록합니다.
5. `/probe/local/clear`를 실행하고 browser를 닫습니다.
6. `curl -D - http://localhost:18080/probe/local/header`와 `/probe/remote/header`의 `X-POV-Set-Cookie-Specimen`을 비교해 두 profile의 exact fresh-session production string을 검토합니다. Production-name cookie를 보낸 negative request가 `409`, `http://127.0.0.1:18080/` Host request가 `421`이며 둘 다 `Set-Cookie`가 없는지도 확인합니다. 두 specimen endpoint 모두 production cookie를 issue하지 않으며 remote specimen은 HTTPS browser compatibility evidence가 아닙니다.

2026-07-25 현재 Codex in-app browser의 `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36` engine에서 primary와 secondary port가 모두 `true`이고 clear 뒤 secondary가 `false`임을 확인했습니다. 이 결과는 해당 Chromium engine의 local HTTP acceptance와 port-isolation 한계만 확정합니다. POV-007의 release support target은 installed Chrome과 Safari이며 두 browser의 AUTH-COOKIE-01이 모두 PASS하기 전 auth delivery를 완료하지 않습니다. Firefox는 설치·지원 결정 전 unsupported이고 AUTH-COOKIE-02는 실제 trusted HTTPS test origin이 생기기 전 conditional입니다.

## Rejected Alternatives

### JWT `alg`를 library default나 token header에 맡김

algorithm confusion과 cross-JWT substitution을 허용할 수 있어 EdDSA/Ed25519 단일 profile을 고정합니다.

### Long-lived bearer 또는 refresh token을 Web Storage에 저장

XSS와 URL/log/cache persistence의 피해 기간을 키우므로 access는 memory-only, refresh는 HttpOnly cookie로 분리합니다.

### Replayed refresh에 grace period 적용

정상 race UX는 좋아지지만 attacker와 response-loss를 구분할 수 없어 strict family revoke와 client single-flight를 선택합니다.

### Local cookie를 remote에서도 재사용하거나 `Secure`를 생략

loopback HTTP의 예외를 외부 network에 확장하므로 origin, name, lifetime과 flags를 분리합니다.

### SameSite만으로 CSRF 방어

same-site와 same-origin은 같지 않고 cookie는 port를 구분하지 않으므로 exact Origin/Host, non-simple header, disabled CORS와 Fetch Metadata를 결합합니다.

### Browser/email recovery 또는 OS access만으로 무조건 reset

새 external identity dependency나 silent account takeover 경로를 만들므로 saved recovery code와 local operator possession을 함께 요구합니다.

## Consequences And Residual Risks

장점:

- owner scope가 token parsing이 아니라 active server session까지 검증된 하나의 issuer boundary를 가집니다.
- short access lifetime, strict refresh rotation과 immediate session lookup이 logout/replay/disable을 새 요청에 즉시 반영합니다.
- local offline flow와 향후 remote HTTPS가 credential을 섞지 않고 같은 auth model을 공유합니다.
- exact values와 test ID가 POV-007/SSE/upload 구현의 executable contract가 됩니다.

비용과 남는 위험:

- local HTTP refresh cookie는 같은 host의 다른 port/process와 격리되지 않습니다. 같은 OS account/process trust가 불충분해지면 local HTTPS 또는 sender-constrained credential ADR이 필요합니다.
- XSS는 memory access token을 최대 10분 동안 사용하거나 사용자를 대신해 same-origin action을 수행할 수 있습니다. CSP와 frontend injection 방어는 구현 review에서 별도로 검증합니다.
- bearer access token은 sender-constrained가 아니며 유효 기간 안의 replay가 가능합니다.
- response loss와 uncoordinated tab refresh는 보안을 위해 session revoke와 re-login을 일으킵니다.
- buggy client나 same-origin XSS가 refresh를 빠르게 반복하면 8,192-generation cap에서 해당 session을 강제 종료할 수 있습니다. 정상 10분 cadence의 30일 local absolute lifetime에는 4,320회 정도이므로 cap은 정상 lifetime보다 높고, 강제 re-login을 수용해 token-row growth를 hard-bound합니다.
- revoke 직전 인증된 bounded request/upload chunk는 완료될 수 있습니다. SSE revoke 전파 상한은 15초입니다.
- 64 MiB Argon2id와 serialized verifier는 reference device benchmark가 필요하며 공격 중 login availability를 낮출 수 있습니다.
- instance-wide throttle은 unknown-ID flood에도 동일하게 반응하므로 attacker가 100회 failure로 owner에게 recovery를 강제할 수 있습니다. local operator recovery와 remote-profile 비활성으로 범위를 제한하며 remote 활성화 전 edge/source rate limit을 새 threat review에서 결정합니다.
- password-only와 saved code는 phishing-resistant MFA가 아니고 독립 notification channel도 없습니다. TOTP/WebAuthn과 remote recovery는 후속 결정입니다.
- password와 saved recovery code를 함께 잃거나 signing key와 saved code를 함께 잃으면 supported recovery가 없으며 account access를 복구하지 못할 수 있습니다. current password가 남아 있을 때만 local code rotation으로 예방할 수 있습니다.
- private signing key는 OS account compromise를 막지 못하며 일반 backup에 포함되지 않습니다. backup/restore와 key escrow는 아직 결정되지 않았습니다.
- remote cookie header는 결정됐지만 Cloudflare logging, cache, trusted edge context와 HTTPS browser behavior를 실제 검증하기 전 remote profile은 비활성입니다.

## Rollback, Supersede And Revisit

ADR-0005가 password blocklist-specific 계약만 부분 supersede했습니다. 그 밖의 auth
implementation 전에는 새 ADR이 이 결정을 supersede할 수 있습니다. 구현 뒤 algorithm,
claim, password parameter, cookie name/path, session lifetime 또는 recovery 변경은
migration, mixed-version validation, forced revoke와 user recovery 영향을 기록한 새
ADR이 필요합니다.

운영 rollback은 secret이나 revoked session을 복원하지 않습니다. unsafe release를 되돌릴 때 accepted keyring/schema를 보존하고, 호환되지 않으면 fail closed한 뒤 explicit operator recovery와 all-session revoke를 수행합니다.

다음 조건에서는 재검토합니다.

- local HTTPS, OS keychain/secure enclave 또는 sender-constrained browser credential을 채택합니다.
- remote ingress를 실제 활성화하거나 trusted proxy/header boundary가 바뀝니다.
- multi-user, shared workspace, public signup, TOTP/WebAuthn 또는 external recovery를 추가합니다.
- Argon2 reference benchmark가 availability 기준을 통과하지 못하거나 hardware class가 바뀝니다.
- XSS, refresh race, key compromise/loss 또는 cookie compatibility failure가 반복됩니다.
- backup/export/restore가 signing key와 auth source를 포함해야 합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [POV-005 completion record](../deps/POV-005-authentication-and-session-security-decision.md)
- [POV-007 implementation ticket](../tickets/POV-007-local-login-refresh-and-session-revoke.md)
- [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 9106 — Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [SQLite — Transaction](https://www.sqlite.org/lang_transaction.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
