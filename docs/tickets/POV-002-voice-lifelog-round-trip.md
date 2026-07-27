# POV-002 MVP Voice Lifelog Round Trip

Status: Planned

Type: Epic

Roadmap: H2 — Correctable voice recall

## Why

첫 제품 가치는 음성을 전사하는 것만이 아니라 사용자가 교정한 기록을 나중에 현재 source와 revision으로 믿고 되찾는 것입니다. 이 왕복이 반복 가치를 만들고 raw audio privacy policy와 local runtime 경계를 함께 지킬 수 있는지 검증합니다.

## What

local Web Chat의 음성 접수부터 전사 교정, 검색, raw audio purge, 다음 날 근거 기반 recall까지 개인 라이프로깅의 첫 product milestone을 end-to-end로 검증합니다. Discord는 이 local core가 검증된 뒤 별도로 추가할 수 있는 선택적 capture adapter입니다.

## User Flow

1. 인증된 사용자가 local Web Chat으로 음성을 보냅니다.
2. idempotent chunk upload가 temporary Blob을 완성합니다.
3. Conversation DB가 media metadata, source hash, job을 기록하고 즉시 접수 상태를 반환합니다.
4. supervised `ffprobe`/`ffmpeg`/Whisper process가 전사합니다.
5. 사용자가 transcript를 교정하면 기존 내용을 덮지 않고 새 revision을 만듭니다.
6. current revision이 FTS5와 embedding index에 증분 반영됩니다.
7. raw audio는 기본 7일 뒤 idempotent하게 purge됩니다.
8. 이후 질의는 current transcript revision과 source reference를 근거로 답합니다.

## Scope

- owner-scoped authenticated upload session과 chunk idempotency
- temporary content-addressed Blob과 media metadata
- Conversation event/job/attempt/transcript revision
- one global execution lease
- process timeout, cancellation, cleanup, runtime/artifact hash
- transcript correction and current revision rules
- KURE candidate, FTS5, normalized vector BLOB, exact cosine baseline
- outbox, stale vector, deletion/purge propagation, reconciliation
- local offline end-to-end flow
- benchmark and audit evidence without personal data

## Out Of Scope

- full Knowledge Service
- Calendar Service
- multi-worker concurrent execution
- broad PWA polish
- permanent raw audio archive
- cloud LLM as required path

## Acceptance Criteria

- same input, upload chunk, event, or job retry does not create duplicates.
- owner isolation holds for conversation, job, media, transcript, search result.
- transcript correction creates immutable revisions and current revision is explicit.
- success, failure, cancellation, timeout leave no orphan process or intermediate WAV.
- inference result records backend, model/artifact revision/hash, runtime build, input hash, elapsed time.
- Embedding failure does not roll back source data and the index can be rebuilt from source DB.
- deleted/corrected source is not returned through stale vectors.
- raw audio purge after the configured default is retry-safe; transcript revision and source hash remain.
- local flow works without internet, Discord, Cloudflare, Obsidian, Calendar, or MCP.
- actual Korean speech and retrieval evaluation gates are versioned before a model candidate becomes release default.
- queue wait and execution time are measured separately; only one job is RUNNING.

## Child Ticket Boundary

이 epic은 다음 child ticket으로 분리합니다.

- [POV-014 Temporary Blob lifecycle and privacy contract](POV-014-temporary-blob-lifecycle-and-privacy-contract.md)
- [POV-015 Authenticated idempotent voice intake](POV-015-authenticated-idempotent-voice-intake.md)
- [POV-033 Windows Python Whisper turbo provider](POV-033-windows-python-whisper-turbo-provider.md)
- [POV-016 Supervised audio normalization and transcription](POV-016-supervised-audio-normalization-and-transcription.md)
- [POV-017 Immutable transcript correction revisions](POV-017-immutable-transcript-correction-revisions.md)
- [POV-018 Current-revision hybrid transcript retrieval](POV-018-current-revision-hybrid-transcript-retrieval.md)
- [POV-019 Retry-safe audio purge](POV-019-retry-safe-audio-purge.md)
- [POV-020 Evidence-grounded next-day recall](POV-020-evidence-grounded-next-day-recall.md)
- [POV-023 Source and derivative reconciliation](POV-023-source-derivative-reconciliation.md)
- [POV-021 Voice round trip evidence gate](POV-021-voice-round-trip-evidence-gate.md)

각 child ticket은 독립 acceptance criteria와 rollback을 가져야 합니다.

## Verification

- Conversation, Embedding, Blob과 공통 owner/source/revision contract test
- upload/job idempotency tests
- process crash/cancel/timeout integration tests
- search revision/deletion regression tests
- purge/reconciliation tests
- offline browser end-to-end test
- reference-device performance benchmark
- staged secret/personal-data/artifact review

## Rollback

child ticket이나 evidence gate가 실패하면 voice capability를 release default로 활성화하지 않습니다. 이미 저장된 Conversation source와 transcript revision을 삭제하지 않고 failed boundary를 좁히거나 first-product hypothesis를 다시 검토합니다. raw audio는 rollback 중에도 accepted retention policy를 계속 따릅니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Product Strategy](../PRODUCT_STRATEGY.md)
- [WBS](../WBS.md)
- [Open Questions](../OPEN_QUESTIONS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
