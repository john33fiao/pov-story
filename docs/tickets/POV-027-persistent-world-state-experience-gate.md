# POV-027 Persistent World State Experience Gate

Status: Gated

Type: Experience gate

Roadmap: H6 — Persistent playable story continuity

Depends on: POV-026 `proceed` or accepted `narrow`

## Why

회차를 넘기는 것만으로는 장기 storyworld value가 생기지 않습니다. 이전 선택, 관계와 세계 상태가 일관되게 이어지고 사용자가 오류를 발견·복구할 수 있어야 단순한 기억 흉내나 무한 chat과 구분됩니다.

## What

관계, 세계 상태, 발견한 사실과 ending condition을 명시적 prototype state로 관리하고 여러 회차·세션에 걸친 continuity 경험을 검증합니다.

> When 이야기에 다시 돌아올 때, I want 인물 관계와 세계가 이전 선택의 결과를 기억하고 설명하기를, so I can 내 행동이 누적되는 하나의 세계라고 신뢰할 수 있다.

## Scope

- relationship, world flag, discovered fact와 ending-condition prototype state
- choice-to-state transition과 다음 회차 rendering
- 여러 세션의 checkpoint, resume와 prior-state recap
- intentional continuity mismatch와 사용자 오류 발견
- reset, replay 또는 correction recovery concept
- informed consent, minimum participant input과 private research retention/deletion
- `proceed`, `narrow`, `fix` 또는 `stop` 결정

## Out Of Scope

- production database, vector memory 또는 model architecture
- unconstrained natural-language memory
- multi-user shared world
- creator marketplace, moderation와 payment
- personal conversation, transcript 또는 lifelog import

## Acceptance Criteria

- prototype state vocabulary, expected transition, participant task와 decision threshold를 test 전에 고정합니다.
- 관계, 세계 상태, 발견과 ending condition이 회차를 넘어 명시적으로 저장·재현됩니다.
- 이전 선택이 후속 회차의 상태나 선택 가능성에 관찰 가능한 영향을 줍니다.
- reference state와 화면/서사 표현을 비교해 continuity success와 hallucinated consistency를 구분합니다.
- 의도적인 mismatch를 사용자가 발견할 수 있는지와 reset/replay/correction 경로를 이해하는지 확인합니다.
- 민감한 실제 lifelog가 아닌 synthetic world만 사용하고 participant input은 최소 수집합니다. consent, access-controlled research storage, retention과 deletion을 research plan에 명시합니다.
- 결과가 creator validation과 architecture decision을 `proceed`, `narrow`, `fix` 또는 `stop`으로 결정합니다.

## Verification

- reference-state transition table과 prototype readback
- cross-session checkpoint/resume walkthrough
- mismatch detection과 recovery evidence traceability
- synthetic fixture, retention와 public-repository safety review
- decision and roadmap readback
- `git diff --check`

## Rollback

`fix`이면 state vocabulary와 recovery interaction만 좁혀 재검증합니다. `stop`이면 POV-028~029를 열지 않고 POV-024에서 H6 disposition을 기록합니다. prototype state와 raw research data는 retention plan에 따라 삭제할 수 있지만 anonymized evidence와 decision은 보존합니다.

## Links

- [H6 Epic — POV-024](POV-024-storyworld-follow-on-outcome.md)
- [Previous — POV-026](POV-026-serialized-story-loop-prototype.md)
- [Next — POV-028](POV-028-creator-authoring-and-monetization-validation.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
