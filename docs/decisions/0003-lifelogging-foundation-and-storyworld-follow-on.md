# ADR-0003: Lifelogging Foundation And Storyworld Follow-on Direction

- Status: Accepted
- Date: 2026-07-25
- Supersedes: [ADR-0002](0002-product-direction-and-repository-identity.md)

## Context

[ADR-0002](0002-product-direction-and-repository-identity.md)는 두 private 기획 노트를 검토한 뒤 local-first 라이프로깅과 AI 스토리월드를 서로 무관한 제품 가설로 분리했습니다. 사용자는 스토리월드가 별도 가설이 아니라 라이프로깅 기반 뒤에 이어질 후속 제품 방향이라고 정정했습니다.

이 정정은 장기 제품 계보를 바꾸지만, 현재 저장소의 구현 우선순위를 즉시 스토리월드로 전환하라는 뜻은 아닙니다. 현재 H-1~H5는 사용자 소유 기록의 capture, correction, source-grounded recall, daily knowledge, time continuity와 safe access를 증명하는 local-first 기반입니다. 후속 방향은 회차, 선택, 분기, 관계와 세계 상태가 이어지는 플레이 가능한 서사 경험입니다.

같은 제품 방향이라는 사실만으로 두 경험이 같은 runtime, DB, account boundary 또는 개인 데이터를 사용해야 하는 것은 아닙니다. shared creator space, cloud inference, 콘텐츠 안전, 저작권, 결제와 정산은 현재 [ADR-0001](0001-architecture-baseline.md)의 single-owner local runtime보다 넓은 별도 결정이 필요합니다.

## Decision

- H-1~H5의 현재 제품·구현 기반은 **독립형 local-first 개인 라이프로깅 웹 챗 앱**으로 유지합니다.
- H6는 별도 제품 가설이 아니라 같은 제품 계보의 **Persistent Playable Story Continuity** 후속 방향입니다.
- H6의 reader outcome은 독자가 연재형 세계의 주인공으로 선택하고, 관계·세계 상태·발견과 엔딩 조건을 회차 사이에 이어 가며 자신이 진행한 이야기로 돌아오는 것입니다.
- H6는 날짜나 release 약속이 아닌 strategic backlog입니다. reader demand, serialized story loop, persistent-state experience, creator authoring과 architecture/safety evidence를 순서대로 검토합니다.
- H6 backlog를 지금 정의하는 것은 실행 시작을 뜻하지 않습니다. H5 outcome evidence를 검토하고 roadmap에서 H6를 명시적으로 우선순위화한 뒤 POV-025를 활성화합니다.
- 초기 H6 검증은 reader experience를 우선합니다. creator marketplace와 monetization은 reader demand와 playable continuity가 증명된 뒤에만 검토합니다.
- H6를 generic character chat, 한 번에 소설을 생성하는 도구 또는 prompt marketplace로 축소하지 않습니다. 핵심 차별화 가설은 회차형 진행, 선택의 후속 효과와 검증 가능한 상태 연속성입니다.
- 이 ADR은 storyworld runtime, schema, provider, deployment 또는 monetization model을 선택하지 않습니다. 현재 [ADR-0001](0001-architecture-baseline.md)의 runtime에 storyworld를 결합하지 않습니다.
- 개인 lifelog source는 storyworld에 자동 입력하거나 암묵적으로 공유하지 않습니다. 명시적 opt-in, 목적 제한, 격리, 철회, export, deletion과 retention 경계는 production 투자 전에 별도 architecture ADR로 결정합니다.
- POV-025~028이 각각 `proceed` 또는 accepted `narrow`일 때만 [POV-029](../tickets/POV-029-storyworld-architecture-and-safety-decision.md)를 엽니다. upstream `pivot` 또는 `stop`은 남은 gate를 열지 않고 POV-024 disposition과 Product Strategy/ADR 재검토로 H6를 닫습니다.
- POV-029 decision이 production 진입을 accepted하기 전에는 storyworld production implementation backlog를 만들지 않습니다.
- `POV Story`는 working title로 유지합니다. 공개 제품명 결정은 별도 naming gate이며 H6의 순서나 data boundary를 암묵적으로 바꾸지 않습니다.

## Rejected Alternatives

### 스토리월드를 계속 별도 제품 가설로 유지

사용자가 명시한 후속 방향을 잃고 라이프로깅에서 플레이 가능한 서사로 확장하려는 장기 제품 의도를 roadmap에 보존하지 못합니다.

### 현재 MVP를 즉시 스토리월드 구현으로 전환

현재 local-first lifelog foundation과 first wedge는 이미 검증 가능한 ticket과 architecture baseline을 가집니다. 수요·playability·continuity evidence 없이 피벗하면 두 방향 모두 학습 가능한 범위를 잃습니다.

### 같은 제품이므로 runtime과 개인 데이터를 자동 공유

제품 계보와 data boundary는 같은 결정이 아닙니다. 민감한 개인 기록을 서사 생성에 자동 사용하는 것은 purpose, consent, deletion과 exposure 위험을 키우며 아직 사용자 가치도 증명되지 않았습니다.

### creator marketplace부터 구축

독자에게 반복되는 playable story value가 없는 상태에서는 authoring workflow, moderation, rights와 settlement에 먼저 투자하게 됩니다. reader-first evidence 뒤에 creator 가설을 검증합니다.

## Consequences

장점:

- 라이프로깅 기반과 스토리월드라는 장기 방향이 하나의 학습 순서로 연결됩니다.
- H0~H5 구현을 방해하지 않으면서 후속 방향이 backlog에서 사라지지 않습니다.
- storyworld 투자 전에 독자, 경험, creator와 architecture risk를 각각 중단 가능한 gate로 검증할 수 있습니다.
- 개인 lifelog와 storyworld data를 자동 결합하지 않아 현재 privacy 경계를 보존합니다.

비용:

- 같은 working title 아래 현재 제품과 후속 경험을 명확히 설명해야 합니다.
- H6 production architecture는 현재 결정되지 않아 evidence gate 뒤에 추가 ADR과 ticket shaping이 필요합니다.
- reader demand가 있어도 moderation, copyright, cost 또는 creator economics 때문에 production 투자를 중단할 수 있습니다.

## Revisit When

- POV-025~029 중 하나가 `pivot`, `defer` 또는 `stop` 결정을 내립니다.
- lifelogging evidence가 H3~H5 또는 H6 순서를 바꿀 만큼 first segment와 North Star를 바꿉니다.
- H6가 개인 lifelog source의 재사용, cloud-only inference, shared workspace 또는 multi-user authoring을 요구합니다.
- H6 production architecture가 ADR-0001의 local-first runtime을 교체하거나 확장해야 합니다.
- 공개 제품명이 현재 foundation과 follow-on direction을 함께 설명하지 못합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Architecture](../ARCHITECTURE.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [H6 Epic — POV-024](../tickets/POV-024-storyworld-follow-on-outcome.md)
- [Correction Ticket — POV-030](../deps/POV-030-storyworld-follow-on-backlog.md)
- [Reference provenance](../refs/README.md)
