# POV-017 Immutable Transcript Correction Revisions

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-004, POV-016

## Why

자동 전사는 틀릴 수 있으며 recall의 근거는 사용자가 확인한 현재본이어야 합니다. 교정이 과거 원문을 덮어쓰거나 concurrent edit를 잃으면 source provenance를 신뢰할 수 없습니다.

## What

local Web Chat에서 expected revision을 기준으로 transcript를 교정하고, immutable 새 revision과 explicit current pointer를 commit한 뒤 readback하는 flow를 구현합니다.

## Scope

- current transcript display and correction form
- expected revision optimistic conflict
- immutable revision append and current pointer
- source audio hash and prior-revision link
- correction audit/correlation metadata
- post-commit readback and safe retry

## Out Of Scope

- collaborative editing
- diff compression
- automatic LLM correction commit
- full audio editor
- search/index update implementation

## Acceptance Criteria

- correction은 기존 transcript revision을 변경하지 않고 새 immutable revision을 만듭니다.
- current pointer는 하나이며 expected revision이 stale하면 자동 덮어쓰기 없이 conflict를 보여줍니다.
- retry가 동일 correction revision을 중복 생성하지 않습니다.
- commit 뒤 readback이 owner, media/source hash, previous/current revision과 text hash를 검증합니다.
- 다른 owner 또는 model output이 current revision을 임의로 변경할 수 없습니다.
- 사용자는 이전 revision과 current status를 구분해 확인할 수 있습니다.

## Verification

- revision append/current invariant tests
- concurrent stale edit and duplicate retry tests
- cross-owner and unauthorized mutation negative tests
- browser correction/readback flow with synthetic transcript
- actual repository validation commands and `git diff --check`

## Rollback

revision을 삭제하거나 과거 내용을 덮어쓰지 않습니다. 문제가 생기면 이전 내용을 새 revision으로 다시 current로 승격하고 audit trail을 보존합니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Roadmap](../WBS.md)
- [POV-016](POV-016-supervised-audio-normalization-and-transcription.md)
- [POV-018](POV-018-current-revision-hybrid-transcript-retrieval.md)
