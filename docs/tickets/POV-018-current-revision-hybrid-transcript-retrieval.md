# POV-018 Current-revision Hybrid Transcript Retrieval

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-006, POV-008, POV-009, POV-017

## Why

교정되거나 삭제된 옛 transcript의 chunk/vector가 검색되면 source가 정확해도 제품 답변은 틀립니다. Embedding failure는 source write를 막지 않아야 하며 derivative는 버리고 다시 만들 수 있어야 합니다.

## What

Conversation outbox에서 current transcript revision을 chunking해 Embedding DB의 FTS5와 normalized vector BLOB에 증분 반영하고 Rust exact cosine 후보를 결합합니다. 결과를 사용하기 전에 current source revision을 다시 확인합니다.

## Scope

- transcript source event consumer and idempotent chunk identity
- versioned chunker/model/dimension/dtype/pooling/normalization metadata
- FTS5 keyword and exact-cosine vector candidates
- current/stale/tombstone derivative state
- owner-scoped query and source reread
- empty Embedding DB full rebuild from Conversation source
- deterministic synthetic Korean retrieval corpus

## Out Of Scope

- final model/quantization release choice
- Knowledge and Calendar indexing
- approximate nearest-neighbor infrastructure
- PostgreSQL/pgvector
- generated natural-language answer

## Acceptance Criteria

- indexing과 query는 owner, source ID와 revision을 보존하고 다른 owner 후보를 반환하지 않습니다.
- current revision 변경 또는 deletion 뒤 이전 derivative가 search result에서 제외됩니다.
- query result는 사용 전에 Conversation source를 다시 읽어 current revision과 active state를 검증합니다.
- embedding failure가 transcript source commit을 rollback하지 않습니다.
- outbox retry가 chunk/vector를 중복 생성하지 않습니다.
- Embedding DB를 비운 뒤 active transcript source에서 동일 metadata contract로 재생성할 수 있습니다.

## Verification

- outbox duplicate/failure/retry tests
- correction, deletion and stale-vector regression tests
- FTS/exact-cosine deterministic corpus tests
- empty-index rebuild and metadata mismatch tests
- actual repository validation commands and `git diff --check`

## Rollback

semantic ranking을 비활성화하고 verified FTS result만 제공하거나 Embedding DB를 폐기 후 재생성할 수 있습니다. Conversation source를 rollback 대상으로 삼지 않습니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-017](POV-017-immutable-transcript-correction-revisions.md)
