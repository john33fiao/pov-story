# POV-030 Storyworld Follow-on Direction And Backlog

Status: Completed

Type: Documentation

Depends on: POV-003

Completed: 2026-07-25

## Why

기존 product-direction 문서는 AI 스토리월드 구상을 라이프로깅 제품과 무관한 별도 가설로 분리했습니다. 사용자는 이를 현재 라이프로깅 기반 뒤에 이어지는 후속 제품 방향으로 명확히 정정했습니다. 현재 MVP 범위를 흔들지 않으면서 장기 방향과 검증 순서를 backlog로 보존해야 합니다.

## What

H0~H5의 local-first 라이프로깅 실행 순서는 유지하고, H6에 플레이 가능한 연재형 스토리월드라는 후속 outcome을 추가합니다. 이전 결정을 새 ADR로 supersede하고, 독자 수요부터 경험 prototype, creator model, architecture와 safety decision까지 review 가능한 backlog로 나눕니다.

## Scope

- storyworld를 별도 제품 가설이 아닌 같은 제품 계보의 H6 후속 방향으로 정의
- ADR-0002를 대체하는 새 product-direction ADR
- H6 outcome, evidence gate, dependency와 backlog
- H6 epic 및 수요·경험·지속 상태·creator·architecture decision child ticket
- README, Product Strategy, Architecture, TODO, WBS, Open Questions, provenance와 local agent guidance 동기화

## Out Of Scope

- 현재 H-1~H5의 순서 또는 local-first 라이프로깅 architecture 변경
- storyworld production code, runtime, schema, 결제 또는 marketplace 구현
- 개인 lifelog를 storyworld 입력으로 자동 재사용
- cloud inference, shared workspace, moderation, age policy, copyright 또는 creator settlement의 선결정
- 외부 시장 수치나 경쟁사 현황의 현재성 조사
- commit, push 또는 pull request

## Acceptance Criteria

- active product 문서가 storyworld를 별도 제품 가설이 아니라 H6 후속 방향으로 일관되게 설명합니다.
- ADR-0002는 이력으로 보존되고 새 ADR이 변경 이유, 유지되는 현재 경계와 재검토 조건을 기록합니다.
- H6는 독자가 회차·분기·관계·세계 상태·엔딩을 이어 가는 outcome과 계속/중단 증거를 가집니다.
- H6 epic과 각 child ticket이 Why, What, 범위, acceptance criteria, verification, rollback과 dependency를 가집니다.
- 수요와 reader experience evidence 전에는 creator marketplace 또는 production architecture를 확정하지 않습니다.
- lifelog source를 storyworld에 자동 연결하지 않으며 향후 명시적 동의, 격리, 삭제·보존 경계를 별도 결정으로 남깁니다.
- private 원문의 본문, 절대 경로, wikilink와 개인 데이터가 public 문서에 복사되지 않습니다.
- README, Product Strategy, Architecture, TODO, WBS, ADR, ticket과 provenance의 링크·상태가 일치합니다.

## Verification

- active 문서의 stale `별도 product hypothesis` 표현 검사
- Markdown 상대 링크와 ticket ID 중복 검사
- ticket 필수 section과 dependency 검사
- private absolute path, secret, 개인 기록과 생성 artifact 유입 검사
- 변경 파일 readback
- `git diff --check`

## Completion Evidence

- ADR-0002를 history로 보존하면서 ADR-0003이 lifelogging H-1~H5 기반과 H6 storyworld 후속 방향을 현재 결정으로 supersede했습니다.
- H6 outcome을 독자가 회차·선택·관계·세계 상태·발견·ending condition을 이어 가는 Persistent Playable Story Continuity로 정의했습니다.
- H5 evidence와 명시적 priority 뒤에 H6를 활성화하며, reader → story loop → persistent state → creator → architecture/safety 순서와 upstream stop path를 WBS/TODO에 기록했습니다.
- POV-024 epic과 POV-025~029 discovery, prototype, experience, creator, decision gate를 WWA와 검증 가능한 acceptance criteria로 작성했습니다.
- personal lifelog 자동 재사용을 금지하고 participant consent/retention, provider training, privacy, moderation, rights, cost와 commerce를 production 전 decision gate로 남겼습니다.
- Markdown link 43개, H6 ticket shape/status, active ticket ID 중복, stale scope 문구, private path/secret pattern, trailing whitespace/conflict marker와 `git diff --check`를 검사했습니다.

## Rollback

이 ticket에서 추가하거나 수정한 문서만 이전 상태로 되돌립니다. ADR-0001과 H0~H5의 local-first 라이프로깅 기준선은 변경하지 않습니다. 새 방향을 다시 바꾸면 ADR 이력을 삭제하지 않고 새 ADR로 supersede합니다.

## Links

- [README](../../README.md)
- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Architecture](../ARCHITECTURE.md)
- [TODO](../TODO.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [ADR-0002](../decisions/0002-product-direction-and-repository-identity.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
- [H6 Epic — POV-024](../tickets/POV-024-storyworld-follow-on-outcome.md)
- [Reader Gate — POV-025](../tickets/POV-025-storyworld-reader-demand-and-positioning.md)
- [Story Loop — POV-026](../tickets/POV-026-serialized-story-loop-prototype.md)
- [Continuity Gate — POV-027](../tickets/POV-027-persistent-world-state-experience-gate.md)
- [Creator Gate — POV-028](../tickets/POV-028-creator-authoring-and-monetization-validation.md)
- [Architecture Gate — POV-029](../tickets/POV-029-storyworld-architecture-and-safety-decision.md)
- [POV-003](POV-003-product-direction-and-outcome-roadmap.md)
