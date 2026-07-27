# POV-004 Core Data Identity And Store Boundary Contracts

Status: Completed

Completed: 2026-07-25

Type: Delivery

Roadmap: H0 — Reproducible local boundary

Depends on: POV-001

## Why

owner, source, revision과 store 경계가 모호하면 이후 retry, correction, search와 deletion에서 다른 사용자의 데이터나 stale derivative를 신뢰하게 됩니다. 첫 domain 기능 전에 안전 규칙을 executable contract로 고정해야 합니다.

## What

공통 owner/source/revision/correlation identifier와 repository port를 정의하고, Conversation, Knowledge, Calendar, Embedding용 SQLite lifecycle과 migration harness를 물리적으로 분리합니다. PostgreSQL은 같은 domain contract를 따를 별도 adapter/migration 경계만 만들고 구현된 것처럼 가장하지 않습니다.

## User Outcome

후속 capture, correction과 recall 기능이 검증된 owner scope와 current source revision을 기준으로만 데이터를 다루고, 한 store의 장애나 derivative 상태를 다른 source store의 권위로 오인하지 않게 됩니다.

## Scope

- 검증된 auth context만 받을 owner scope contract
- UUID-typed identifier, source identity, immutable revision과 correlation ID
- 네 SQLite WAL file의 독립 migration history와 lifecycle
- DB별 blocking executor, integrity setting과 backup hook contract
- source store와 derivative store의 repository boundary
- synthetic repository contract fixture

## Out Of Scope

- login, JWT 또는 refresh 구현
- 완성된 Conversation, Knowledge, Calendar domain schema
- PostgreSQL production adapter
- embedding model 또는 search ranking
- 실제 개인 데이터 migration

## Acceptance Criteria

- request body, URL 또는 model output의 owner ID가 authorization source가 될 수 없습니다.
- 네 store는 별도 file, migration history와 repository boundary를 가지며 cross-DB join 또는 distributed transaction을 제공하지 않습니다.
- SQLite connection은 WAL, foreign key, busy timeout과 DB별 blocking execution policy를 검증합니다.
- source identity와 revision으로 derivative를 stale 처리하거나 재생성할 수 있는 contract가 정의됩니다.
- PostgreSQL adapter와 migration namespace가 SQLite SQL과 분리되고 미구현 상태가 명확합니다.
- synthetic contract test가 owner isolation, revision conflict와 store separation을 검증합니다.

## Definition Of Done

- backend-neutral repository port의 operation이 opaque verified-owner scope 없이는 호출되지 않습니다.
- 네 store의 create/open/reopen/migration/backup lifecycle과 fail-closed negative case가 실제 temporary SQLite file 또는 in-memory migration에서 검증됩니다.
- `pov-api` runtime wiring, production auth issuer와 실제 domain record persistence를 구현한 것으로 보고하지 않습니다.
- README, architecture, TODO, WBS, dependency link와 이 ticket의 completion evidence가 최종 changed set과 일치합니다.
- 아래 실제 validation과 project-local RTD After가 모두 통과한 뒤 completed archive로 이동합니다.

## Verification

- `npm --prefix web run format:check`
- `npm --prefix web run lint`
- `npm --prefix web run typecheck`
- `npm --prefix web run build`
- `cargo fmt --all -- --check`
- `cargo check --locked --workspace --all-targets`
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `cargo test --locked --workspace --all-targets`
- `cargo build --locked --workspace --release`
- `sh scripts/smoke.sh`
- `git diff --check`

## Completion Evidence

- `pov-core`는 UUID-typed owner ID, 생성·persisted rehydration에서 RFC UUID v4를 검증하는 source/correlation ID, SQLite `INTEGER` 범위의 positive checked revision과 owner-bound source revision을 제공합니다.
- `VerifiedAuthContext`는 private field와 `cfg(test)` synthetic issuer만 가지며 production constructor는 없습니다. shared-receiver async backend-neutral repository port의 read/create/revise operation은 raw `OwnerId`가 아니라 이 opaque context에서 얻은 scope를 요구하고 generic backend failure를 표현합니다. interior-mutable synthetic repository가 같은 port를 구현합니다. production auth issuer와 transport enforcement는 POV-007 범위로 남겼습니다.
- Conversation, Knowledge, Calendar source store와 Embedding derivative store는 typed marker가 source/derivative 역할을 분리합니다. source-store marker는 associated domain을 노출하며 각 store는 고정 file과 독립 migration SQL/history/namespace를 가집니다. concrete domain record adapter는 아직 없습니다.
- clean open, close/reopen, app initialization reservation guard drop, synthetic interrupted-empty recovery와 committed store의 leftover-marker recovery, markerless formatted-empty/foreign DB, invalid initialization marker, valid marker의 foreign schema 채택 거부, wrong-store contract, migration exact-prefix·SQL drift와 future migration을 실제 temporary SQLite file로 검증합니다. recognized store 또는 허용된 빈 초기 상태 확인 전에는 app이 WAL mode를 바꾸거나 migration을 적용하지 않습니다.
- connection은 store별 전용 blocking thread에서 직렬 실행하며 WAL, `synchronous=FULL`, foreign key, 5초 busy timeout, `trusted_schema=OFF`, cell-size check, defensive mode와 integrity를 fail closed로 재검증합니다.
- migration 전에 설치한 SQLite authorizer는 exact `SQLITE_AUTH`로 `ATTACH`/`DETACH`를 항상 거부하고 migration SQL의 transaction/savepoint 제어와 value-setting PRAGMA도 막습니다. commit 직전 전체 current history 재검증은 같은 migration에서 이전 history를 변조하는 시도를 rollback합니다. synthetic migration rollback, FK orphan, cross-owner read/mutation과 stale revision update도 fail closed임을 확인합니다.
- source revision freshness는 exact owner/domain/source/revision일 때만 current이며 stale revision은 현재 source를 regeneration target으로, source 부재는 별도 missing state로 반환합니다.
- Unix에서 새 store root, DB와 initialization marker는 `0700`/`0600`으로 만들고 기존 불안전한 root를 변경하지 않고 거부하며 root symlink와 DB symlink/hard-link alias를 따라가지 않습니다. main/destination 부재 preflight에서 발견한 orphan DB/backup sidecar는 삭제하지 않고 보존하며 초기화·backup을 거부합니다. current attempt가 main을 예약한 뒤 생긴 conventional sidecar path는 failure cleanup 대상이고, main DB cleanup이 실패하면 recovery marker를 보존합니다.
- online backup hook은 기존 destination을 덮어쓰지 않고 store 하나의 row snapshot을 만든 뒤 store contract, 전체 current migration history와 `quick_check`를 검증합니다. invalid snapshot과 partial artifact cleanup 실패를 보고하며 dispatch 뒤 caller future 취소 시 worker completion은 계속될 수 있습니다. encryption, retention, multi-store publication과 restore policy는 구현하지 않았습니다.
- PostgreSQL은 별도 namespace와 typed `NotImplemented` 상태만 제공하며 driver나 migration SQL은 없습니다.
- fixture, DB, WAL, SHM과 backup artifact는 test temporary directory에만 생성되고 repository changed set에는 남지 않습니다.
- 실제 Tokio task abort, subprocess/power-loss와 multi-process contention은 직접 harness하지 않았습니다. initialization marker는 recovery token이지 exclusive lock은 아니므로 concurrent opener가 있는 동안 creator의 failed-open/drop cleanup이 reserved main과 sidecar를 unlink할 수 있습니다. 기존 main을 첫 read/write handle로 열 때 SQLite hot-journal/WAL recovery가 app identity 검사보다 앞설 수도 있습니다. private `0700` root와 아직 없는 runtime store wiring이 현재 exposure를 제한하며, exclusive initialization ownership과 crash/concurrency harness는 wiring 전 conditional residual로 남깁니다.

## Rollback

runtime store wiring과 domain record가 아직 없으므로 `pov-core`, workspace dependency, migration harness와 synthetic fixture를 함께 되돌릴 수 있습니다. 실제 데이터가 생긴 뒤에는 migration file을 삭제하거나 번호를 재사용하지 않고 후속 migration과 superseding decision으로 변경합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [POV-001](POV-001-local-offline-walking-skeleton.md)
