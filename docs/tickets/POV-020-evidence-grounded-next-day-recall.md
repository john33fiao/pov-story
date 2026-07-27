# POV-020 Evidence-grounded Next-day Recall

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-012, POV-018

## Why

첫 제품 가치는 transcript를 저장하는 데서 끝나지 않고, 나중에 질문했을 때 현재 원문을 근거로 과거 맥락을 믿고 되찾는 데 있습니다. 근거가 없을 때 추측하지 않는 것도 성공 조건입니다.

## What

local Web Chat의 자연어 질문에서 owner-scoped transcript 후보를 찾고 current source를 재검증한 뒤, source date와 revision을 포함한 검색 결과 또는 생성 답변을 제공합니다.

## Scope

- recall query job and owner-scoped retrieval
- current source/revision post-filter
- grounded prompt context and provenance
- source date/revision reference in UI
- insufficient/conflicting evidence response
- deleted/stale/cross-owner exclusion
- deterministic non-generative fallback

## Out Of Scope

- Knowledge, Calendar 또는 general web search
- long-term memory promotion
- autonomous mutation
- final retrieval quality threshold
- broad citation UX polish

## Acceptance Criteria

- answer와 result는 사용한 current transcript source ID, revision과 date를 사용자에게 표시합니다.
- deleted, stale와 다른 owner source가 context나 output에 포함되지 않습니다.
- 근거가 없거나 충돌하면 사실을 만들지 않고 부족함과 가능한 source를 구분합니다.
- generation failure 시 verified retrieval result를 잃지 않고 non-generative fallback을 제공합니다.
- 같은 recall retry가 source event, job 또는 assistant result를 중복 생성하지 않습니다.
- internet, Discord, Obsidian, Calendar와 MCP 없이 local Web Chat에서 완료됩니다.

## Verification

- grounded, insufficient, conflicting and deleted-source scenarios
- cross-owner and stale-revision negative tests
- generation failure fallback and retry idempotency tests
- offline browser flow with synthetic Korean records
- actual repository validation commands and `git diff --check`

## Rollback

generated narrative를 끄고 verified source list와 excerpt만 표시할 수 있습니다. search/source data를 삭제해 rollback하지 않습니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Roadmap](../WBS.md)
- [POV-018](POV-018-current-revision-hybrid-transcript-retrieval.md)
