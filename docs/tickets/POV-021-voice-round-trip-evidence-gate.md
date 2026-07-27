# POV-021 Voice Round Trip Evidence Gate

Status: Planned

Type: Evidence gate

Roadmap: H2 — Correctable voice recall

Depends on: POV-015 through POV-020, POV-023

## Why

Knowledge, Calendar와 remote product로 확장하기 전에 voice capture와 source-grounded recall이 실제 반복 가치를 만들고 privacy, quality와 local performance 경계를 함께 지키는지 확인해야 합니다.

## What

POV-002 전체 flow의 versioned Korean evaluation, reference-device benchmark와 dogfood evidence를 모읍니다. 표본, success threshold와 stop rule을 측정 전에 고정하고 결과를 `ship`, `narrow`, `fix` 또는 `stop`으로 결정합니다.

## Scope

- OMTM definition and pre-registered sample/threshold
- Korean transcription and current-revision retrieval corpus
- capture, correction, recall and purge dogfood sequence
- source/revision, owner, deletion and idempotency guardrail
- source/derivative reconciliation evidence
- queue-wait versus execution-time benchmark
- reference-device memory and artifact provenance
- qualitative setup/correction/recall friction
- decision record, blocker and residual risk

## Out Of Scope

- threshold를 결과에 맞춰 사후 변경
- personal raw data를 repository fixture로 commit
- Knowledge/Calendar implementation
- public launch 또는 monetization
- model candidate를 benchmark 없이 release invariant로 선언

## Acceptance Criteria

- sample, metric, pass threshold와 stop rule이 evaluation 실행 전에 versioned artifact로 고정됩니다.
- Voice Recall Loop Success Rate와 North Star proxy를 재현 가능한 입력과 결과로 계산할 수 있습니다.
- cross-owner exposure, deleted/stale source exposure, duplicate mutation과 accepted purge grace/SLA 밖의 raw audio guardrail이 모두 평가됩니다.
- transcription/retrieval quality, correction effort, queue wait, execution latency와 memory pressure가 분리되어 기록됩니다.
- 실패하거나 실행하지 못한 conditional check를 PASS로 보고하지 않습니다.
- 결과가 H3 ticketize 여부와 voice scope를 `ship`, `narrow`, `fix` 또는 `stop` 중 하나로 결정합니다.

## Verification

- versioned synthetic/anonymized evaluation set and runner
- offline end-to-end on the declared reference device
- retention/purge and process crash/cancel regression
- staged secret, personal-data, model-weight and generated-artifact review
- repository-documented validation and `git diff --check`

## Rollback

gate가 실패하면 voice capability를 release default로 켜지 않고 H3 상세 ticket을 만들지 않습니다. source data를 삭제하지 않고 결과에 따라 좁은 corrective ticket 또는 strategy review를 엽니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Roadmap](../WBS.md)
- [POV-019](POV-019-retry-safe-audio-purge.md)
- [POV-020](POV-020-evidence-grounded-next-day-recall.md)
- [POV-023](POV-023-source-derivative-reconciliation.md)
