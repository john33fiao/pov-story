# POV-023 Source And Derivative Reconciliation

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-008, POV-009, POV-017, POV-018

## Why

outbox retry, correction과 deletion failure가 active source의 missing derivative나 inactive revision의 stale vector를 남길 수 있습니다. purge와 별개인 이 failure domain을 독립적으로 탐지하고 repair해야 source-grounded recall을 신뢰할 수 있습니다.

## What

Conversation source, outbox와 Embedding derivative를 비교해 missing, duplicate, stale와 tombstoned state를 분류하고 idempotent repair 또는 exclusion을 수행하는 reconciliation job을 구현합니다.

## Scope

- source/current revision versus derivative inventory
- missing outbox/chunk/vector detection
- stale/tombstoned derivative exclusion
- duplicate derivative collapse by stable identity
- idempotent repair enqueue and bounded cursor
- crash, cancel and restart-safe progress
- synthetic mismatch fixtures and audit summary

## Out Of Scope

- raw audio or Blob purge
- source revision mutation
- Knowledge and Calendar source reconciliation
- ranking-quality tuning
- full backup/restore

## Acceptance Criteria

- active current source의 missing derivative를 탐지해 idempotent repair 대상으로 만듭니다.
- inactive, corrected 또는 deleted source의 derivative가 query에서 제외되고 안전하게 cleanup됩니다.
- duplicate outbox delivery나 reconciliation retry가 chunk/vector를 추가 중복 생성하지 않습니다.
- source DB가 권위이며 reconciliation이 source text, owner 또는 revision을 derivative 값으로 덮어쓰지 않습니다.
- crash/cancel 뒤 cursor와 audit summary로 남은 범위를 계속 처리할 수 있습니다.
- Embedding DB가 완전히 비었을 때의 rebuild와 부분 mismatch repair를 구분합니다.

## Verification

- missing, duplicate, stale, tombstoned and metadata-mismatch matrix
- retry/crash/cancel/restart integration tests
- cross-owner and derivative-authority negative tests
- empty-index rebuild versus partial-repair tests
- actual repository validation commands and `git diff --check`

## Rollback

repair scheduler를 중지하고 query-time current-source validation을 계속 적용합니다. Embedding DB는 source DB를 변경하지 않고 폐기 후 재생성할 수 있습니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-018](POV-018-current-revision-hybrid-transcript-retrieval.md)
