# ADR-0002: Product Direction And Repository Identity

- Status: Superseded by [ADR-0003](0003-lifelogging-foundation-and-storyworld-follow-on.md)
- Date: 2026-07-25

> 이 문서는 2026-07-25 당시의 결정을 보존합니다. 사용자가 storyworld를 별도 가설이 아닌 lifelogging 기반 이후의 후속 방향으로 정정해 현재 결정은 [ADR-0003](0003-lifelogging-foundation-and-storyworld-follow-on.md)을 따릅니다.

## Context

사용자가 명시적으로 제공한 두 private 기획 노트는 `POV Story`라는 이름 아래 서로 다른 제품을 설명합니다.

- 하나는 메모, 음성, 일정, 할 일, 작업일지와 장기 기억을 앱 소유 저장소에서 다루는 local-first 개인 라이프로깅 제품이며, 현재 저장소와 [ADR-0001](0001-architecture-baseline.md)의 기준선입니다.
- 다른 하나는 회차, 분기, 관계, 세계 상태와 creator marketplace를 포함하는 AI 스토리월드 제품 가설이며, 자체 결론에서 구현보다 수요 검증이 먼저인 보류 아이디어입니다.

두 제품은 첫 사용자, 핵심 JTBD, 데이터·운영 경계, monetization과 위험이 다릅니다. 이름만 같다는 이유로 하나의 roadmap에 합치면 현재 accepted architecture와 첫 수직 기능의 의미가 사라집니다.

## Decision

- 이 저장소의 단일 제품은 **독립형 local-first 개인 라이프로깅 웹 챗 앱**입니다.
- 첫 activation 가설은 local Web Chat의 한국어 음성 capture, transcription correction, current-revision indexing, source-grounded recall과 raw audio expiry입니다.
- local Web Chat은 필수 제품 채널입니다. Discord는 Conversation Core와 voice value를 증명한 뒤 capture 마찰을 줄이는지 별도로 검증할 선택적 adapter입니다.
- AI 스토리월드, 캐릭터 채팅, 에피소드·엔딩 수집과 creator marketplace는 이 저장소의 feature 또는 Later milestone이 아닙니다.
- 스토리월드 구상을 다시 검토할 때는 별도 discovery track과 저장소를 우선하고, 이 저장소를 전환하려면 이 ADR과 ADR-0001을 대체하는 명시적 결정이 필요합니다.
- `POV Story`는 현재 working title로 유지합니다. 공개 제품명 결정은 별도 product naming gate이며 제품 범위를 암묵적으로 바꾸지 않습니다.
- first segment와 voice wedge는 H1 전에 discovery gate로 검증합니다. Knowledge, Calendar, remote PWA와 optional tools의 상세 ticket은 voice recall evidence gate를 통과한 뒤 작성합니다.

## Rejected Alternatives

### 두 제품을 하나의 장기 roadmap으로 합침

스토리월드의 shared creator space, cloud-scale generation, moderation, 결제와 콘텐츠 운영은 single-owner local lifelog의 범위를 확대하는 정도가 아니라 다른 제품과 architecture를 요구합니다.

### 이 저장소를 즉시 스토리월드 제품으로 전환

스토리월드 원문은 구현 전에 수요 검증을 요구하고 현재 우선순위를 낮게 둡니다. 반면 라이프로깅 방향은 상세한 requirements, accepted architecture와 첫 구현 ticket이 있습니다.

### 이름 충돌을 해결하지 않고 구현만 시작

같은 이름을 근거로 이후 agent가 스토리 기능을 backlog에 섞거나 accepted boundary를 우회할 위험이 있습니다.

## Consequences

장점:

- product strategy, architecture, outcome roadmap과 ticket이 하나의 사용자 문제를 향합니다.
- POV-001과 POV-002를 폐기하지 않고 첫 learning sequence로 사용할 수 있습니다.
- storyworld의 수요 검증을 현재 runtime과 결합하지 않고 독립적으로 판단할 수 있습니다.
- local Web Chat과 선택적 Discord adapter의 우선순위가 명확해집니다.

비용:

- `POV Story`라는 working title이 storyworld 제품을 연상시키는 명칭 부채로 남습니다.
- Knowledge와 Calendar 같은 넓은 기능은 voice wedge의 가치가 검증될 때까지 상세 일정이 없습니다.
- storyworld를 선택하려면 별도 discovery와 architecture 작업이 필요합니다.

## Revisit When

- 사용자가 이 저장소를 스토리월드 제품으로 전환하라고 명시적으로 결정하고 사전 수요 증거를 제공합니다.
- voice capture와 source-grounded recall이 반복 사용을 만들지 못해 첫 제품 wedge를 바꿔야 합니다.
- first segment가 외부 앱 sync, cloud inference 또는 shared workspace 없이는 핵심 가치를 얻지 못합니다.
- working title이 사용자 이해나 배포를 방해해 public product naming을 확정해야 합니다.

## Links

- [Superseding ADR-0003](0003-lifelogging-foundation-and-storyworld-follow-on.md)
- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Architecture](../ARCHITECTURE.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [Reference provenance](../refs/README.md)
