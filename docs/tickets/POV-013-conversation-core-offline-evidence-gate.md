# POV-013 Conversation Core Offline Evidence Gate

Status: In Progress — `fix`; POV-040, full rerun and target-Chrome evidence required

Type: Evidence gate

Roadmap: H1 — Trustworthy text capture

Depends on: POV-004 through POV-012

## Why

voice upload와 transcription 복잡도를 추가하기 전에 auth, durable source, single-slot queue, local Web Chat과 failure recovery가 실제로 함께 동작한다는 증거가 필요합니다.

## What

clean checkout, offline text capture, owner isolation, idempotent retry, token refresh, status reconnect와 provider crash를 하나의 versioned evidence pack으로 검증하고 H2 진입을 `proceed`, `fix` 또는 `stop`으로 결정합니다.

## Scope

- documented clean setup and build
- local login, capture, job and assistant round trip
- internet/external-app-off regression
- owner spoofing and cross-owner negative cases
- retry, lease expiry, token refresh and stream reconnect
- provider crash/cancel/timeout cleanup
- result summary, blocker and residual risk

## Out Of Scope

- voice/audio
- model quality comparison
- Knowledge or Calendar
- Cloudflare and remote browser
- production personal data

## Acceptance Criteria

- POV-001과 POV-004~012의 executable acceptance evidence가 실제 command/result로 연결됩니다.
- local core flow는 internet, Discord, Obsidian, Calendar와 MCP 없이 완료됩니다.
- cross-owner exposure, duplicate source/job과 simultaneous execution-slot occupancy가 없습니다.
- refresh/reconnect와 process failure 뒤 durable source와 terminal state가 보존됩니다.
- unrun slow/conditional check는 PASS로 표시하지 않고 blocker와 residual risk를 기록합니다.
- H2 진입 결정과 실패 시 열어야 할 좁은 corrective ticket이 명시됩니다.

## Preregistered Evidence Matrix

검증 대상은 exact commit
`70ad66146a7f47dde3157ed0089ef8316e81e8ee`입니다. Evidence 문서 변경과 검증 대상을
섞지 않기 위해 이 commit의 detached clean worktree에서 명령을 실행합니다.
Matrix text는 command 실행 전에 working tree에 작성했지만 stage/commit 승인을 선행하지
않았으므로 결과와 별도 commit으로 고정됐다고 주장하지 않습니다. Target SHA와 threshold는
실행 중 변경하지 않았습니다.

고정 환경은 macOS `26.5.2` (`25F84`, arm64), Rust/Cargo `1.95.0`, Node.js `26.4.0`,
npm `11.17.0`입니다. Installed-browser evidence는 Google Chrome `150.0.7871.187` 한
조합으로만 제한합니다. 다른 macOS 또는 browser 조합의 지원을 추론하지 않습니다.

| ID | Evidence boundary | Exact command or observation | Immutable threshold | Result |
| --- | --- | --- | --- | --- |
| E01 | clean target | `git status --porcelain=v1 -uall` and `git rev-parse HEAD` in the detached worktree | no changed/untracked path; exact target SHA | PASS |
| E02 | offline dependency restore | `npm --prefix web ci --offline` | completes without registry or external-app access | PASS |
| E03 | frontend baseline | `npm --prefix web run format:check`, `lint`, `test`, `typecheck`, `build` | every command exits 0 | PASS |
| E04 | browser reconnect contract | `npm --prefix web run test:browser` | refresh/reload cursor resumes; persisted bearer-token canary count `0` | FAIL — current event linkage fixture is stale |
| E05 | Rust baseline | `cargo fmt --all -- --check`; `CARGO_NET_OFFLINE=true cargo check --locked --workspace --all-targets`; `KDF_TEST_SERIAL=1 CARGO_NET_OFFLINE=true cargo test --locked --workspace --all-targets -- --test-threads=1` | every command exits 0; ignored/conditional tests remain explicitly reported | FAIL — no one execution boundary completed the full suite |
| E06 | generation atomicity and retry | targeted `generation_dispatch_completion_is_atomic_idempotent_and_persistent` and `enqueue_replay_conflict_and_cross_owner_access_fail_closed` tests | duplicate source/job `0`; cross-owner exposure `0`; reopen preserves exact terminal result | PASS |
| E07 | queue serialization and recovery | targeted single-slot lease/expiry/recovery tests plus full locked suite | simultaneous running slot maximum `1`; uncertain cleanup halts dispatch | PASS |
| E08 | owner-scoped status reconnect | targeted owner cursor/SSE tests and Web reconnect tests | foreign exposure `0`; refresh/reconnect preserves durable terminal state | FAIL — Rust owner cursor PASS, Web reconnect FAIL |
| E09 | provider failure cleanup | targeted fake-provider start/restart/crash/timeout/cancel tests | each failure is distinct; orphan listener/process count `0` after every case | PASS |
| E10 | target Chrome offline core | user-controlled production `auth init`, production binary and Chrome flow with Wi-Fi disabled | login → synthetic save → queue → assistant → authoritative readback succeeds; external request count `0` | NOT RUN — fail-fast after E04/E05 |
| E11 | target Chrome recovery | access expiry, one refresh, SSE reconnect and page reload | exactly one refresh recovery; reconnect cursor and durable terminal state preserved | NOT RUN — fail-fast after E04/E05 |
| E12 | repository safety | changed/staged diff, tracked-file and generated-artifact review | credential, personal data, DB/Blob/log/model artifact count `0`; `git diff --check` and relative Markdown links pass | PARTIAL — unstaged review PASS; staged review pending approval |

`E10`과 `E11`에서는 password, recovery code, token, cookie value, KID, owner record, local
instance path, model path/hash 또는 raw browser trace를 기록하지 않습니다. Synthetic text,
aggregate count, version, command exit status와 redacted observation만 tracked evidence로
남깁니다. Linux 전용 `scripts/test_operator_pty.py`와
`scripts/test_production_auth_smoke.py`는 이 macOS 결과의 PASS 근거가 아닙니다.

## Decision Rules

- `proceed`: `E01`~`E12`가 모두 PASS이고 duplicate, cross-owner exposure, orphan process와
  credential/personal-data/model-artifact 유입이 모두 `0`입니다.
- `fix`: 재현 가능한 implementation failure, offline restore failure 또는 필수 evidence가
  하나라도 FAIL/UNAVAILABLE입니다. 같은 causal boundary만 다루는 corrective ticket을
  만들고 POV-014와 H2를 열지 않습니다.
- `stop`: owner isolation, durable source 보존 또는 fail-closed cleanup처럼 H1의 핵심
  전제가 안전하게 복구될 수 없다는 evidence가 있을 때만 사용합니다.

POV-038은 macOS controlling-TTY initialization, second-init no-replace와 exact Chrome
cookie/storage/cache support claim을 별도로 소유합니다. Credential/token 노출처럼 두
경계를 함께 깨는 실패는 두 ticket을 모두 차단하지만, 실행하지 않은 browser 조합이나
macOS support 표기는 POV-013 결과로 확대하지 않습니다.

## Evidence Result

Final decision: **fix**

### Executed Evidence

- Detached clean checkout는 exact target SHA와 empty porcelain status를 확인했습니다.
- `npm ci --offline`과 frontend format/lint/unit/typecheck/build는 모두 PASS했고 unit test는
  `13/13` PASS였습니다.
- Targeted generation, queue, owner cursor와 provider cleanup tests는 모두 PASS했습니다.
  Duplicate source/job, cross-owner exposure와 orphan listener/process 관찰값은 각각 `0`,
  simultaneous running slot maximum은 `1`이었습니다.
- Playwright는 sandbox loopback 제한을 해제한 재실행에서도 `1/1` FAIL했습니다. Event parser가
  요구하는 `conversation_id`와 `source_event_id`가 fixture payload에 없어 app이 frame을
  fail closed하고 `상태 다시 연결 중`에 머문 것이 root cause입니다.
- KDF-serialized full Rust suite는 sandbox에서 process-group signal `PermissionDenied`로
  process tests 3건이 실패했습니다. Host에서 process suite만 재실행하면 `22` PASS,
  `15` helper ignored, `0` FAIL이었지만 full host run은 raw non-UTF-8 artifact tests 2건이
  `Illegal byte sequence (os error 92)`로 실패했습니다. 두 raw test는 sandbox에서 각각
  단독 PASS했으므로 component evidence를 보존하되 required full command를 PASS로
  확대하지 않습니다.
- Release `pov-api` build는 offline locked mode에서 PASS했습니다. E04/E05 mandatory blocker가
  확정되어 credential-bearing production initialization과 installed-Chrome manual flow는
  실행하지 않았습니다.
- Unstaged changed set의 credential/private-key pattern, generated/runtime artifact,
  `git diff --check`와 relative Markdown link review는 PASS했습니다. Stage하지 않았으므로
  staged diff review는 실행하지 않았습니다.

### Corrective Tickets And Residual Risk

- [POV-039](POV-039-repair-job-status-browser-evidence-fixture.md)는 stale Playwright fixture만
  current owner-scoped event schema와 맞춥니다. Production parser를 완화하지 않습니다.
- [POV-040](POV-040-reconcile-macos-raw-filename-validation.md)은 target MacBook의 raw filename
  `EILSEQ`와 process execution boundary를 한 full baseline으로 재조정합니다. Unknown/raw
  artifact fail-closed contract를 완화하지 않습니다.
- E10/E11을 실행하지 않았으므로 macOS production auth, installed Chrome, offline asset,
  refresh-cookie/storage/cache claim은 모두 미검증 상태입니다. POV-038은 완료가 아니라
  `Ready`로 유지합니다.
- POV-014와 H2는 POV-039/040 수정과 POV-013 전체 재실행에서 `proceed`가 나오기 전까지
  열지 않습니다.

### POV-039 Remediation Update — 2026-08-01

- [POV-039](POV-039-repair-job-status-browser-evidence-fixture.md)는 Playwright `statusEvent`에
  current schema의 canonical UUID v4 `conversation_id`와 `source_event_id`만 추가해
  완료했습니다. Production parser, SSE/API schema와 runtime behavior는 변경하지 않았습니다.
- Current worktree에서 browser `1/1`, Web unit `13/13`, frontend format/lint/typecheck/build,
  `git diff --check`와 changed Markdown relative-link check가 PASS했습니다. Refresh handoff,
  reconnect cursor, reload, malformed-linkage rejection과 bearer-token non-persistence assertion은
  그대로 유지했습니다.
- 이 remediation은 exact `70ad66146a7f47dde3157ed0089ef8316e81e8ee` matrix의 E04/E08
  FAIL을 PASS로 덮어쓰지 않으며 POV-013 전체 재실행도 아닙니다. POV-040, full matrix rerun과
  E10/E11 target-Chrome evidence가 남아 있으므로 final decision은 계속 **fix**입니다.

## Verification

- repository-documented fast validation
- offline browser end-to-end
- auth/retry/stream/process failure integration suite
- staged secret, personal-data and generated-artifact review
- `git diff --check`

## Rollback

gate가 실패하면 voice ticket을 Ready로 바꾸지 않습니다. Conversation Core data를 삭제하지 않고 failed boundary만 좁은 ticket으로 수정합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Roadmap](../WBS.md)
- [POV-002](POV-002-voice-lifelog-round-trip.md)
- [POV-012](POV-012-loopback-llm-text-round-trip.md)
- [POV-022](POV-022-first-segment-and-voice-wedge-discovery-gate.md)
