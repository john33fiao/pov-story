# POV-024 Storyworld Follow-on Outcome

Status: Planned

Type: Epic

Roadmap: H6 — Persistent playable story continuity

Activation gate: H5 outcome evidence and explicit H6 roadmap prioritization

## Why

라이프로깅 기반 이후의 장기 제품 방향이 active backlog에 없으면 storyworld 구상이 다시 별도 아이디어로 밀려나거나, 반대로 검증 없이 현재 MVP에 섞일 수 있습니다. 후속 방향을 하나의 reader outcome과 중단 가능한 evidence sequence로 소유해야 합니다.

## What

독자가 연재형 세계의 주인공으로 들어가 선택하고, 관계·세계 상태·발견과 엔딩 조건을 회차 사이에 누적하며 자신이 진행한 이야기로 돌아오는 H6 outcome을 관리합니다.

> When 독자가 연재형 세계에 다시 들어올 때, I want 이전 선택과 관계가 다음 회차에 일관되게 이어지기를, so I can 남이 만든 이야기를 소비하는 대신 내가 진행한 이야기로 경험할 수 있다.

## Scope

- reader-first storyworld outcome과 초기 positioning
- 회차, 장면, 선택, 분기와 checkpoint/resume
- 관계, 세계 상태, 발견과 ending-condition continuity
- reader demand와 반복 의향 검증
- evidence 뒤의 creator authoring 및 monetization 검증
- production 투자 전 architecture, data, safety와 operations decision

## Out Of Scope

- H-1~H5 lifelogging roadmap의 대체 또는 우선순위 자동 변경
- generic character chat을 최종 제품으로 삼기
- 한 번에 소설을 생성하는 범용 도구
- prompt만 사고파는 marketplace
- 개인 lifelog source의 자동 import 또는 암묵적 재사용
- POV-029 이전 production runtime, schema, payment 또는 marketplace 구현

## Child Backlog

- [POV-025 Reader demand and positioning](POV-025-storyworld-reader-demand-and-positioning.md)
- [POV-026 Serialized story loop prototype](POV-026-serialized-story-loop-prototype.md)
- [POV-027 Persistent world state experience gate](POV-027-persistent-world-state-experience-gate.md)
- [POV-028 Creator authoring and monetization validation](POV-028-creator-authoring-and-monetization-validation.md)
- [POV-029 Architecture and safety decision](POV-029-storyworld-architecture-and-safety-decision.md)

## Acceptance Criteria

- Product Strategy, WBS와 TODO가 H6를 별도 제품 가설이 아닌 후속 방향으로 연결합니다.
- H6 desired outcome은 feature 수가 아니라 reader가 회차 사이의 선택과 상태 연속성을 경험하는 결과로 정의됩니다.
- 각 child ticket은 선행 evidence, continue/stop rule과 다음 gate를 가집니다.
- reader demand와 playable continuity가 확인되기 전에는 creator marketplace를 production commitment로 만들지 않습니다.
- POV-029 decision 전에는 storyworld production implementation ticket을 만들지 않습니다.
- 현재 lifelog North Star, architecture와 H-1~H5 실행 backlog는 별도 결정 없이 바뀌지 않습니다.
- 같은 제품 계보가 같은 runtime, DB 또는 개인 데이터 공유를 의미하지 않는다고 명시합니다.

## Exit Criteria

- H5 outcome evidence 뒤에 H6 activation 여부가 명시적으로 결정됩니다.
- POV-025~028이 각각 `proceed` 또는 accepted `narrow`이면 POV-029가 H6를 `proceed`, `narrow`, `defer` 또는 `stop`으로 닫습니다.
- upstream gate가 `pivot` 또는 `stop`이면 남은 child를 열지 않고 epic disposition, evidence와 재검토 조건을 Product Strategy/WBS/ADR에 기록합니다.
- POV-029가 production 진입을 accepted한 경우에만 별도 production epic을 만들고, 그 외에는 no-go 또는 defer 결정을 보존합니다.

## Verification

- Product Strategy, WBS, TODO와 ADR-0003 readback
- child dependency와 status 검사
- active 문서의 stale separate-hypothesis 표현 검사
- public-repository data-safety 검사
- `git diff --check`

## Rollback

H6 evidence가 `pivot`, `defer` 또는 `stop`이면 production backlog를 만들지 않습니다. upstream `pivot` 또는 `stop`은 남은 gate를 `Not opened`로 두고 이 epic에서 disposition을 기록합니다. child evidence와 결정 이력은 보존하고 current lifelogging roadmap은 계속 운영합니다. 장기 방향 변경은 ADR-0003을 삭제하지 않고 새 ADR로 supersede합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [TODO](../TODO.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
