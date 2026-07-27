# POV-015 Authenticated Idempotent Voice Intake

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-013, POV-014

## Why

사용자는 큰 음성 upload가 중단되어도 안전하게 재개하고 즉시 durable receipt를 받아야 합니다. retry가 media, Blob 또는 transcription job을 중복 생성해서는 안 됩니다.

## What

owner-scoped upload session, bounded idempotent chunk, finalize hash verification, temporary Blob, Conversation media metadata와 transcription job을 잇는 local Web Chat voice intake를 구현합니다.

## Scope

- authenticated upload session and expiry
- configured maximum chunk/object size and owner quota
- chunk number/hash idempotency and resume
- safe temporary path and content-addressed finalize
- media source metadata, input hash and one transcription job
- immediate durable receipt and failure state

## Out Of Scope

- transcription execution
- waveform/editor polish
- Discord upload
- permanent audio archive
- broad non-audio attachment

## Acceptance Criteria

- token refresh와 reconnect 뒤 같은 upload/session/chunk를 중복 없이 재개할 수 있습니다.
- 같은 chunk number에 다른 content hash가 오면 기존 object를 변경하지 않고 conflict를 반환합니다.
- size, type, quota, session expiry와 final hash가 server-side에서 검증됩니다.
- path traversal, original filename path와 cross-owner upload 접근이 거부됩니다.
- successful finalize는 temporary Blob, media metadata와 transcription job을 각각 하나만 만듭니다.
- storage/finalize/job failure를 성공으로 표시하지 않고 retry 가능한 durable state로 남깁니다.

## Verification

- chunk replay, conflict, out-of-order, resume and finalize tests
- size/quota/type/hash/path and cross-owner negative tests
- token expiry during upload browser test
- receipt and duplicate job integration test
- actual repository validation commands and `git diff --check`

## Rollback

신규 upload session 발급을 중지합니다. 완성된 temporary object는 accepted retention에 따라 보존·purge하고 DB metadata를 임의 삭제하지 않습니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Roadmap](../WBS.md)
- [POV-014](POV-014-temporary-blob-lifecycle-and-privacy-contract.md)
