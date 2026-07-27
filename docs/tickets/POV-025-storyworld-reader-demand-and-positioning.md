# POV-025 Storyworld Reader Demand And Positioning

Status: Gated

Type: Discovery gate

Roadmap: H6 — Persistent playable story continuity

Parent: POV-024

Activation gate: H5 outcome evidence and explicit H6 roadmap prioritization

## Why

storyworld에 대한 일반적 호감만으로는 독자가 character chat이나 자동 생성 소설 대신 회차형 playable story에 반복해서 돌아올지 알 수 없습니다. prototype과 운영 투자 전에 첫 reader segment, 문제, 대안과 다음 회차 의도를 direct evidence로 검증해야 합니다.

## What

서로 다른 초기 세계·장르 concept, 첫 회차와 다음 회차 preview를 사용해 reader problem, positioning과 행동 의도를 검증합니다.

> When 새로운 세계에 몰입할 경험을 찾을 때, I want 내 선택이 다음 회차와 관계에 영향을 주는 이야기를, so I can 수동 소설이나 끝없는 자유 대화와 다른 진행 감각을 얻을 수 있다.

## Scope

- initial reader problem과 current alternative interview
- 작은 world/genre concept set과 serialized playable-story concept test
- generic character chat, 수동 interactive fiction과 one-shot AI story generation 대비 positioning
- 첫 회차 진입, 다음 회차 재방문, waitlist 또는 prototype 참여 행동
- 호감, 반복 의향, 지불 의향을 분리한 evidence
- informed consent, data minimization, private research storage와 retention/deletion plan
- first reader segment와 initial genre의 `proceed`, `narrow`, `pivot` 또는 `stop` 결정

## Out Of Scope

- production story generation 또는 persistent-state implementation
- statistically representative market sizing
- 현재 경쟁사·시장 규모에 대한 검증되지 않은 주장
- creator authoring tool, marketplace, payment 또는 settlement
- 실제 개인 lifelog data 사용

## Acceptance Criteria

- participant profile, sample, concept 수, decision threshold와 stop rule을 research 전에 고정합니다.
- reader의 현재 대안, 불편, 원하는 진행 구조와 재방문 계기를 직접 발화와 관찰 evidence로 구분합니다.
- 단순한 concept 호감, 다음 회차를 보기 위한 행동, prototype 참여와 지불 의향을 같은 지표로 합치지 않습니다.
- generic chat이 아니라 회차·선택·후속 효과라는 positioning을 사용자가 이해하는지 확인합니다.
- first reader segment와 initial genre를 근거와 함께 `proceed`, `narrow`, `pivot` 또는 `stop`으로 결정합니다.
- anonymized finding만 저장하고 identity, private conversation, local path와 copyrighted source text를 public repository에 넣지 않습니다.
- consent, contact, raw response와 research artifact는 최소 수집하며 public repository 밖의 access-controlled location, retention과 deletion 시점을 research plan에 기록합니다.
- `proceed` 또는 명시적인 `narrow` 결정만 POV-026의 gate를 엽니다.

## Verification

- pre-registered research plan과 decision rule review
- concept, interview와 behavior evidence traceability
- alternative-positioning readback
- anonymization, copyright와 public-repository safety review
- Product Strategy와 WBS decision readback
- `git diff --check`

## Rollback

결과가 `pivot` 또는 `stop`이면 POV-026~029를 시작하지 않고 POV-024에서 H6 disposition과 재검토 조건을 기록합니다. `narrow`이면 segment, genre와 value proposition을 Product Strategy와 이 ticket에 먼저 반영합니다. concept artifact는 retention plan에 따라 제거할 수 있지만 anonymized evidence와 decision history는 보존합니다.

## Links

- [H6 Epic — POV-024](POV-024-storyworld-follow-on-outcome.md)
- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
- [Next — POV-026](POV-026-serialized-story-loop-prototype.md)
