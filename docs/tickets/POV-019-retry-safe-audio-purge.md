# POV-019 Retry-safe Audio Purge

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-014 through POV-017

## Why

기본 retention은 수동 정리로 지킬 수 없습니다. purge retry나 missing Blob이 transcript를 잃게 하거나 raw audio를 accepted grace 밖에 남기면 privacy와 recall을 동시에 훼손합니다.

## What

expiry와 accepted purge grace가 지난 raw audio와 intermediate object를 idempotent하게 제거하고 Blob metadata와 transcript source의 lifecycle state를 재조정합니다.

## Scope

- due temporary-audio selection and idempotent purge
- partial/intermediate object cleanup
- purge result, tombstone and audit metadata
- missing Blob versus missing source distinction
- retry, crash and restart-safe cursor/state
- synthetic clock and isolated fixture store

## Out Of Scope

- permanent raw audio recovery
- general account deletion
- backup/restore implementation
- Embedding/outbox derivative reconciliation
- retention policy change

## Acceptance Criteria

- configured expiry가 지난 due raw audio는 retry와 restart 뒤에도 한 번의 효과로 제거됩니다.
- accepted purge cadence와 grace 밖의 due raw audio가 다음 successful run 뒤 남지 않습니다.
- purge 뒤 transcript revisions, current pointer, source hash와 audit evidence가 보존됩니다.
- Blob missing은 source DB loss로 취급하지 않고 idempotent completed/reconciled state로 처리됩니다.
- crash/cancel 중 일부 object만 처리되어도 다음 run이 나머지를 계속 처리합니다.
- live clock 없이 synthetic fixture로 irreversible-delete behavior를 검증할 수 있습니다.

## Verification

- synthetic-clock due/not-due and retry tests
- crash-between-delete-and-commit recovery tests
- missing Blob, partial upload and metadata mismatch matrix
- transcript/source preservation assertions
- actual repository validation commands and `git diff --check`

## Rollback

scheduler를 중지해 신규 purge를 멈출 수 있지만 이미 삭제된 raw audio 복원을 보장하지 않습니다. rollback과 repair는 transcript/source/derivative metadata를 보존하는 forward action으로 수행합니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Roadmap](../WBS.md)
- [POV-014](POV-014-temporary-blob-lifecycle-and-privacy-contract.md)
- [POV-017](POV-017-immutable-transcript-correction-revisions.md)
