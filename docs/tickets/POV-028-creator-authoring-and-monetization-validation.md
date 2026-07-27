# POV-028 Creator Authoring And Monetization Validation

Status: Gated

Type: Discovery gate

Roadmap: H6 — Persistent playable story continuity

Depends on: POV-025 and POV-027 each `proceed` or accepted `narrow`

## Why

reader demand가 있어도 creator가 회차, 분기, 관계와 엔딩을 지속적으로 설계·수정·배포할 수 없다면 marketplace 방향은 운영되지 않습니다. prompt 판매와 다른 authoring value, 제작 부담, 게시 의향과 monetization 의향을 production 도구 전에 검증해야 합니다.

## What

구조화된 world/episode authoring template과 concierge workflow로 creator가 짧은 playable path를 만들고 수정하도록 하며 제작 가능성과 monetization 가설을 검증합니다.

> When 인터랙티브 세계를 만들 때, I want 회차·선택·관계·엔딩을 구조적으로 설계하고 수정하기를, so I can prompt가 아니라 독자가 계속 진행할 수 있는 경험을 배포할 수 있다.

## Scope

- target creator problem과 current authoring alternative
- world premise, episode, scene, choice, branch, relationship와 ending template
- 최소 playable path의 작성, test, revision과 handoff walkthrough
- 제작 시간, 오류, 수정 부담과 publishing intent
- 일회 구매, 회차, 구독 또는 후원 같은 monetization 후보에 대한 분리된 evidence
- informed consent, creator IP permission, private research storage와 retention/deletion
- creator ownership, attribution, update, moderation와 settlement open-risk capture
- `proceed`, `narrow`, `pivot` 또는 `stop` 결정

## Out Of Scope

- production creator studio, marketplace, payment 또는 settlement
- monetization model이나 가격 확정
- copyrighted source의 무단 복제 또는 실제 권리 계약
- public user-generated content 운영
- AI가 creator 승인 없이 world를 게시·수정

## Acceptance Criteria

- creator profile, task, artifact 범위, success threshold와 stop rule을 research 전에 고정합니다.
- creator가 구조화된 template으로 최소 두 회차와 한 개 이상의 meaningful branch를 작성하거나 수정합니다. meaningful branch는 후속 state, available choice 또는 ending condition 중 하나를 바꿉니다.
- output이 prompt 묶음이 아니라 world, episode, state transition과 ending condition을 포함합니다.
- 제작 시간, 도움 요청, 구조 오류, revision과 publishing intent를 관찰 evidence로 기록합니다.
- creator의 실시간 도움 없이 reader가 결과 path를 replay하고 선언된 state/ending transition과 reference trace가 일치합니다.
- 제품 사용 의향과 monetization·수익 기대를 같은 evidence로 합치지 않습니다.
- monetization behavioral proxy와 no-signal 처리 규칙을 research 전에 고정하고, 실제 결제 없이도 관찰 가능한 행동 또는 증거 부재를 명시합니다.
- copyright, ownership, attribution, moderation, versioning, takedown, refund와 settlement는 미결정 risk로 남기고 production 약속을 하지 않습니다.
- creator consent, raw response, 연락처와 unpublished artifact는 public repository에 넣지 않고 permission, access-controlled storage, retention과 deletion을 research plan에 기록합니다.
- 결과가 POV-029의 creator/commerce 범위를 `proceed`, `narrow`, `pivot` 또는 `stop`으로 결정합니다.

## Verification

- authoring template과 created-path structural review
- creator walkthrough evidence traceability
- reader prototype에서 path replay
- rights, safety, anonymization와 public-repository review
- monetization claim/evidence separation review
- `git diff --check`

## Rollback

`pivot` 또는 `stop`이면 POV-029를 열지 않고 POV-024에서 H6 reader-only 전환 또는 no-go disposition을 기록합니다. template, unpublished artifact와 raw research data는 permission/retention plan에 따라 폐기할 수 있지만 anonymized learning, rights risk와 decision history는 보존합니다.

## Links

- [H6 Epic — POV-024](POV-024-storyworld-follow-on-outcome.md)
- [Reader Gate — POV-025](POV-025-storyworld-reader-demand-and-positioning.md)
- [Continuity Gate — POV-027](POV-027-persistent-world-state-experience-gate.md)
- [Next — POV-029](POV-029-storyworld-architecture-and-safety-decision.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
