# Product Strategy

Status: Product direction baseline

Last reviewed: 2026-07-25

## Direction Decision

POV Story의 현재 구현 기반은 **독립형 local-first 개인 라이프로깅 웹 챗 앱**입니다.

이 저장소에서 사용자는 텍스트와 음성으로 기록을 남기고, 교정하고, 나중에 현재 revision과 source를 확인하며 다시 찾습니다. 메모, daily note, task, worklog, memory와 calendar는 이 핵심 경험을 확장하는 앱 내부 기능입니다.

이 기반 이후의 H6 후속 방향은 **Persistent Playable Story Continuity**입니다. 독자는 연재형 세계의 주인공으로 선택하고, 관계·세계 상태·발견과 엔딩 조건을 회차 사이에 이어 가며 자신이 진행한 이야기로 돌아옵니다. 이는 별도 제품 가설이 아니라 같은 제품 계보의 장기 방향이지만, 현재 MVP 기능이나 production architecture commitment는 아닙니다.

현재 H-1~H5의 lifelogging scope와 North Star는 유지합니다. H6 backlog는 지금 보존하되 H5 outcome evidence와 명시적 roadmap priority 뒤에 활성화합니다. 그 뒤 reader demand, story loop, persistent state, creator authoring과 architecture/safety evidence를 순서대로 통과해야 합니다. 같은 제품 계보가 같은 runtime·DB 또는 개인 lifelog의 자동 재사용을 뜻하지는 않습니다. `POV Story`는 working title이며 공개 제품명 결정은 별도 gate입니다.

이 방향, 순서와 재검토 조건은 [ADR-0003](decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)에 기록합니다.

## Product Strategy Canvas

### 1. Vision

사람이 하루 동안 남긴 파편적인 생각, 말, 할 일과 결정을 자신의 장치 안에서 안전하게 이어 붙이고, 필요할 때 근거와 함께 되찾을 수 있게 합니다.

우리가 지키는 가치는 다음과 같습니다.

- **소유권**: 앱 소유 저장소가 정본이며 외부 서비스 장애나 정책에 핵심 기록을 맡기지 않습니다.
- **신뢰**: 모델의 그럴듯함보다 source, revision, correction, readback을 우선합니다.
- **연속성**: capture에서 recall과 후속 행동까지 하나의 대화 흐름으로 연결합니다.
- **독립성**: 인터넷, Obsidian, 운영체제 Calendar, Discord, MCP 없이도 핵심 흐름이 동작합니다.
- **절제**: 검증되지 않은 자동화와 기능 확장보다 작은 안전한 수직 기능을 먼저 증명합니다.

### 2. Market Segments

현재 세그먼트 정의는 인터뷰 결과가 아니라 원문 요구사항과 제품 경계에서 도출한 가설입니다.

| Priority | Problem-defined segment | JTBD | Why now |
| --- | --- | --- | --- |
| First | 민감한 개인 기록이 여러 앱과 서비스에 흩어져 있고 직접 통제하기 원하는 1인 사용자 | 생각과 음성을 한 대화창에 빠르게 남기고, 나중에 현재 원문과 수정 이력을 믿으며 다시 찾고 싶다 | single-owner, local-first, voice recall이라는 가장 좁은 제품 가설을 검증할 수 있음 |
| Next | 음성 메모와 회의·작업 기록 비중이 높은 지식노동자 또는 개인 아카이버 | 긴 음성을 교정 가능한 기록으로 바꾸고 과거 결정과 맥락을 다시 활용하고 싶다 | 첫 voice round trip이 성공한 뒤 반복 사용과 검색 품질을 검증할 수 있음 |
| Later | local source of truth를 유지하면서 여러 장치나 외부 위치에서 접근하려는 self-hosting 사용자 | 데이터 소유권을 포기하지 않고 안전하게 원격 접근하고 싶다 | local product value와 backup/recovery가 먼저 증명되어야 함 |
| Follow-on | 선택의 결과가 이어지는 연재형 세계에 반복해서 돌아오려는 interactive-story reader, 이후 이를 설계하려는 creator | 회차를 소비하는 대신 주인공으로 선택하고 관계·세계 상태·엔딩을 이어 가고 싶다 | H6 reader demand와 continuity를 먼저 증명한 뒤 creator 방향을 검증 |

interactive-story reader와 creator는 현재 H-1~H5의 target segment가 아닙니다. [POV-025](tickets/POV-025-storyworld-reader-demand-and-positioning.md)가 H6의 first reader와 initial genre를 evidence로 좁힙니다.

### 3. Relative Costs

최저 비용이나 가장 많은 모델 호출보다 **개인 데이터 통제, offline 가용성, 검증 가능한 변경**이라는 고유 가치를 선택합니다.

- cloud inference 종속과 사용량 기반 비용을 핵심 경로에서 피합니다.
- local setup과 기준 장치의 연산 비용은 신뢰와 소유권을 위한 명시적 trade-off입니다.
- 초기에는 한 사용자, 한 control plane, 전역 실행 슬롯 하나로 운영 복잡도를 제한합니다.
- 고가 모델이나 다중 worker는 측정된 품질·latency·queue 병목이 있을 때만 검토합니다.
- 사업 모델과 가격은 현재 검증 범위가 아니며, unit economics를 확정된 사실처럼 가정하지 않습니다.
- H6의 generation, moderation, creator operations와 commerce 비용은 현재 local runtime 비용과 합치지 않고 POV-029에서 evidence 기반으로 결정합니다.

### 4. Value Proposition

| Element | First segment |
| --- | --- |
| What before | 메모, 음성, 할 일, 일정과 장기 기억이 서로 다른 앱에 흩어지고, 나중에 어떤 원문과 수정본이 맞는지 확인하기 어렵습니다. |
| How | 하나의 local Web Chat이 앱 소유 DB에 owner-scoped source와 revision을 기록하고, 교정·검색·readback·보존 정책을 코드로 강제합니다. |
| What after | 사용자는 인터넷이나 외부 앱 없이 기록을 남기고, 현재 source와 revision을 근거로 과거 맥락을 되찾아 다음 행동으로 이어갈 수 있습니다. |
| Alternatives | 수동 메모와 파일 검색, 외부 메모·Calendar 조합, cloud AI memory, 음성 파일을 영구 보관하고 사람이 다시 듣는 방식 |

첫 activation 가설은 다음 왕복입니다.

> local Web Chat에서 한국어 음성을 남긴다 → 전사를 교정한다 → 검색에 반영한다 → 나중에 현재 revision과 source를 근거로 다시 찾는다 → raw audio는 정책에 따라 만료된다

### 5. Trade-offs

현재 H-1~H5 전략은 다음을 의도적으로 하지 않습니다.

- H6 evidence와 architecture decision 전의 storyworld production 구현, creator marketplace 또는 payment
- 개인 lifelog source를 storyworld prompt, memory 또는 training data로 자동 재사용
- 외부 메모 앱이나 운영체제 Calendar를 정본 또는 양방향 sync 대상으로 사용
- cloud LLM이 없으면 동작하지 않는 핵심 경로
- 모델이 owner, 저장 범위, revision, 승인 또는 삭제 정책을 결정하는 자율 agent
- raw audio 영구 보존
- MVP의 다중 사용자 공유 공간과 여러 동시 실행 작업
- 검증 전의 이미지·음성 생성, web search와 광범위한 외부 tool

이 거절은 현재 기록 신뢰성과 local 독립성에 역량을 집중하면서 H6를 검증 가능한 후속 방향으로 보존합니다.

### 6. Key Metrics

**North Star Metric — 주간 검증된 라이프로그 회수·활용 성공 수**

한 주 동안 이전에 저장한 기록을 다시 찾아 현재 source와 revision을 확인하고, 사용자가 조회·교정·후속 기록 같은 의도한 행동을 완료한 고유 outcome 수입니다. 단순 대화 횟수나 token 사용량은 포함하지 않습니다.

**Current OMTM — Voice Recall Loop Success Rate**

versioned acceptance 및 dogfood case 중 음성 접수, 전사, 교정, current-revision 검색, 근거 표시와 recall을 수동 DB 복구 없이 완료한 비율입니다. 목표 임계치와 표본은 측정 전에 [POV-021](tickets/POV-021-voice-round-trip-evidence-gate.md)에서 고정합니다.

Guardrail:

- 다른 owner의 source 또는 상태 노출: 0
- 삭제되거나 stale한 revision의 검색·답변 노출: 0
- 같은 idempotency key의 중복 mutation: 0
- accepted purge grace/SLA 밖의 due raw audio 잔존: 0
- 인터넷과 외부 앱이 없는 local 핵심 흐름 실패: 0

latency, model quality와 reference-device memory는 제품 가치와 별도의 release gate로 측정합니다. 후보값을 성공 지표로 고정하지 않습니다.

### 7. Growth

현재 목표는 사용자 수 확대가 아니라 한 명에게 반복되는 신뢰 가능한 가치가 있는지 확인하는 것입니다.

1. 저장소 소유자의 synthetic 및 dogfood flow로 correction, recall, purge와 offline 경계를 검증합니다.
2. 작은 privacy-conscious 사용자 집단에서 setup 부담, capture 빈도와 verified recall을 관찰합니다.
3. local value와 recovery가 증명된 뒤 안전한 remote PWA 접근을 추가합니다.
4. 반복 사용과 운영 비용이 확인된 뒤 distribution, contribution, 가격 또는 monetization을 별도로 검토합니다.
5. H6에서는 작은 concept와 serialized prototype으로 reader demand, 다음 회차 행동과 state continuity를 검증합니다.
6. reader evidence가 통과한 뒤 creator authoring을 검증하고, 마지막에만 production architecture와 commerce 투자를 결정합니다.

초기 성장 방식은 product-led self-hosting과 명시적 초대에 가깝습니다. Discord는 acquisition channel이나 정본이 아니라, local Web Chat의 가치가 증명된 뒤 capture 마찰을 줄이는지 확인할 선택적 adapter입니다.

### 8. Capabilities

반드시 직접 구축할 역량:

- owner-scoped domain command와 source/revision/idempotency 검증
- Conversation, Knowledge, Calendar source store와 재생성 가능한 Embedding 경계
- correction, deletion, readback, outbox와 reconciliation
- local process supervision, timeout/cancel/cleanup과 artifact provenance
- offline same-origin Web Chat과 개인정보를 cache하지 않는 client
- source-grounded retrieval 평가와 backup/restore/purge 검증

교체 가능한 외부 구성요소:

- LLM, STT와 embedding runtime 및 model artifact
- FFmpeg 계열 media utility
- 선택적 Discord capture adapter
- 선택적 Cloudflare remote ingress

외부 구성요소는 provider 또는 adapter 뒤에 두며 source of truth가 되지 않습니다.

H6가 evidence gate를 통과하면 검토할 후보 역량:

- episode, scene, choice, branch와 checkpoint/resume
- relationship, world state, discovered fact와 ending-condition revision
- creator world/episode authoring, versioning과 publishing
- storyworld generation provenance, safety, quota와 cost control

이 목록은 현재 architecture contract가 아닙니다. [POV-029](tickets/POV-029-storyworld-architecture-and-safety-decision.md)가 구현 전에 bounded context와 source-of-truth 경계를 결정합니다.

### 9. Can't / Won't

H6에서도 다음 shortcut을 제품의 종착점으로 삼지 않습니다.

- 맥락 없이 이어지는 generic character chat
- 한 번에 결과물만 만드는 “AI가 소설을 써 주는” generator
- playable reader value 없이 prompt만 거래하는 marketplace
- 동의 없이 개인 lifelog를 이야기 재료로 가져오는 기능

현재 기반의 초기 방어력은 network effect나 독점 모델이 아니라 **검증된 개인 기록의 연속성과 신뢰 workflow**에서 나옵니다.

- 시간이 쌓일수록 source, revision, correction과 typed relation이 개인 맥락을 형성합니다.
- local/offline, post-commit readback, stale-source 차단과 purge를 함께 지키는 운영 규율은 단일 cloud chat 기능보다 복제 비용이 큽니다.
- versioned 한국어 command, transcription과 retrieval evaluation corpus는 품질 개선 역량이 됩니다.
- 동시에 export와 교체 가능한 provider를 보장해 데이터 lock-in 자체를 방어력으로 삼지 않습니다.

이 방어력은 아직 가설입니다. verified recall이 반복되지 않으면 축적 데이터가 있어도 제품 우위가 되지 않습니다.

## Strategy Coherence

single-owner와 local-first 범위는 네 source/derivative 경계, 전역 실행 슬롯 하나, voice-first wedge와 서로 강화됩니다. source-grounded recall을 North Star로 삼기 때문에 correction, current revision, deletion propagation, raw audio purge는 기술 부채가 아니라 제품 가치의 일부입니다.

H6 storyworld는 이 연속성 원리를 개인 기록에서 플레이 가능한 서사 상태로 확장하는 후속 방향입니다. 그러나 shared multi-user 공간, cloud-scale 생성, moderation, 결제와 creator operations가 필요할 수 있으므로 현재 전략과 runtime에 곧바로 기능으로 섞지 않습니다. lifelogging foundation → reader demand → playable loop → persistent state → creator → architecture decision의 순서가 두 방향을 연결합니다.

## Critical Hypotheses And Low-effort Experiments

| Hypothesis | Low-effort test | Evidence to continue | Stop or revisit signal |
| --- | --- | --- | --- |
| 하나의 chat capture가 여러 외부 앱보다 덜 번거롭다 | Phase 1 text flow를 짧은 기간 dogfood하고 capture 실패·우회 횟수를 기록 | 반복 capture와 이후 recall이 발생 | 사용자가 계속 외부 앱을 정본으로 사용 |
| voice recall은 첫 activation으로 충분히 가치 있다 | 같은 내용을 keyboard와 voice로 남기고 다음 날 source-grounded recall을 비교 | 음성이 capture 마찰을 줄이고 교정 후 재사용됨 | 전사 교정 비용이 절감 시간보다 큼 |
| correction과 source 표시가 신뢰를 높인다 | source/revision을 보이거나 숨긴 prototype의 오류 발견과 수정 행동 비교 | 사용자가 잘못된 recall을 찾아 안전하게 교정 | source 표시가 이해되지 않거나 행동을 바꾸지 않음 |
| local-first 가치가 setup과 성능 비용을 상쇄한다 | clean-checkout setup과 offline reference-device flow를 관찰 | 도움 없이 재현 가능하고 기준 SLO 안에서 사용 가능 | 설치·모델 실행 부담 때문에 핵심 흐름을 포기 |
| raw audio 기본 7일 purge가 기대와 맞는다 | purge 전 알림·export가 없는 최소 정책을 설명하고 dogfood 피드백 수집 | transcript 보존만으로 충분하고 purge가 신뢰를 높임 | 원음을 장기 정본으로 요구 |
| 외부 앱 sync 없이도 핵심 가치가 성립한다 | 인터넷, Obsidian, Calendar와 Discord를 끈 회귀 flow 수행 | capture와 recall이 동일하게 완료 | 외부 정본 연동 없이는 반복 사용이 성립하지 않음 |
| 독자는 generic chat보다 회차와 선택의 후속 효과가 있는 storyworld를 원한다 | world concept와 첫/다음 회차 preview를 비교하고 재방문 행동을 관찰 | 다음 회차 행동과 prototype 참여가 단순 호감과 구분됨 | 호감은 있으나 회차형 진행 행동이 없음 |
| persistent relationship/world state가 반복 사용 가치를 만든다 | synthetic 두 회차 prototype에서 reference state와 resume 경험 비교 | 사용자가 이전 선택의 효과를 이해하고 다시 돌아옴 | continuity가 중요하지 않거나 오류가 신뢰를 무너뜨림 |
| creator는 prompt가 아니라 playable world 구조를 제작·수정할 수 있다 | structured authoring template과 concierge workflow 수행 | creator가 회차·분기·관계·엔딩을 만들고 수정·게시하려 함 | 제작 부담이나 권리·운영 risk가 reader value를 넘음 |

## Review Gates

- [POV-022](tickets/POV-022-first-segment-and-voice-wedge-discovery-gate.md)에서 first segment, voice wedge, correction/source trust와 purge expectation을 검증한 뒤 H1 delivery ticket을 Ready로 올립니다.
- [POV-013](tickets/POV-013-conversation-core-offline-evidence-gate.md)에서 text Conversation Core의 안전성과 offline 흐름을 통과한 뒤 voice intake를 시작합니다.
- [POV-021](tickets/POV-021-voice-round-trip-evidence-gate.md)에서 첫 activation 가설을 검토한 뒤 Knowledge와 Calendar 티켓을 구체화합니다.
- H5 outcome evidence를 검토하고 H6를 명시적으로 우선순위화한 뒤 [POV-025](tickets/POV-025-storyworld-reader-demand-and-positioning.md)를 활성화합니다.
- [POV-025](tickets/POV-025-storyworld-reader-demand-and-positioning.md)에서 H6 first reader와 positioning을 검증한 뒤 story loop prototype을 시작합니다.
- [POV-026](tickets/POV-026-serialized-story-loop-prototype.md)과 [POV-027](tickets/POV-027-persistent-world-state-experience-gate.md)에서 playability와 continuity를 통과한 뒤 creator 가설을 검증합니다.
- POV-025~028이 각각 `proceed` 또는 accepted `narrow`일 때만 [POV-029](tickets/POV-029-storyworld-architecture-and-safety-decision.md)를 열고, 그 decision이 production 진입을 accepted한 뒤에만 implementation backlog를 작성합니다.
- first-segment evidence, North Star 또는 핵심 trade-off가 바뀌면 이 문서와 ADR을 함께 갱신합니다.

## Links

- [Architecture](ARCHITECTURE.md)
- [Outcome Roadmap And WBS](WBS.md)
- [Live TODO](TODO.md)
- [ADR-0001](decisions/0001-architecture-baseline.md)
- [ADR-0003](decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
- [Superseded ADR-0002](decisions/0002-product-direction-and-repository-identity.md)
- [Reference provenance](refs/README.md)
