# POV-014 Temporary Blob Lifecycle And Privacy Contract

Status: Planned

Type: Decision

Roadmap: H2 — Correctable voice recall

Depends on: POV-013

## Why

raw audio는 민감하고 purge 뒤 복구할 수 없습니다. live voice intake 전에 encryption, path, quota, retention, playback/export와 irreversible deletion의 경계를 결정해야 합니다.

## What

app-managed content-addressed Blob의 owner scope, at-rest protection, upload/processing state, configured size and quota, 기본 7일 audio retention, purge와 failure recovery를 ADR과 executable lifecycle test matrix로 확정합니다.

## Scope

- Blob object identity, owner scope와 metadata boundary
- content-addressed path and filesystem permission policy
- encryption at rest decision and key dependency
- upload/chunk/object size, owner quota and free-space behavior
- temporary audio expiry, playback/export window, purge cadence, grace/SLA and overdue semantics
- partial upload, intermediate file and crash cleanup
- backup exclusion/inclusion and missing-object reconciliation policy

## Out Of Scope

- upload endpoint
- production audio 저장
- transcription
- permanent raw audio archive
- general attachment retention

## Acceptance Criteria

- accepted decision이 encryption, key failure, permission, retention, quota, low-disk와 purge behavior를 명확히 정합니다.
- `due`, `overdue`와 policy violation을 expiry, scheduler cadence와 accepted grace/SLA로 재현 가능하게 정의합니다.
- original filename이나 사용자 path가 object path 또는 authorization 근거가 되지 않습니다.
- default audio expiry는 정책으로 강제되며 사용자가 모르게 무기한 연장되지 않습니다.
- purge가 irreversible임을 UI와 operator에게 알리고 retry-safe delete contract를 정의합니다.
- partial upload, intermediate output, missing Blob와 DB metadata mismatch의 recovery behavior가 정의됩니다.
- synthetic lifecycle test와 residual privacy risk가 기록됩니다.

## Verification

- ADR and threat-model review
- synthetic create/finalize/expire/delete/retry/missing-object matrix
- path traversal, quota and low-disk abuse cases
- link and `git diff --check`

## Rollback

live intake 전에는 decision을 supersede할 수 있습니다. live data 뒤에는 retention을 짧게 바꾸거나 encryption contract를 제거하기 전에 migration, user notice와 irreversible-delete 영향을 새 ADR로 다룹니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Open Questions](../OPEN_QUESTIONS.md)
- [Roadmap](../WBS.md)
- [POV-013](POV-013-conversation-core-offline-evidence-gate.md)
- [POV-015](POV-015-authenticated-idempotent-voice-intake.md)
