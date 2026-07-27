# POV-026 Serialized Story Loop Prototype

Status: Gated

Type: Prototype gate

Roadmap: H6 — Persistent playable story continuity

Depends on: POV-025 `proceed` or accepted `narrow`

## Why

concept demand가 있어도 독자가 대화가 아니라 이야기 진행 구조를 이해하고, 자신의 선택 때문에 다음 회차를 계속하고 싶은지는 별도 가설입니다. production LLM과 backend를 만들기 전에 최소 prototype으로 핵심 loop를 관찰해야 합니다.

## What

synthetic world에서 장면을 읽고 선택하며 분기 결과를 본 뒤 checkpoint에서 다음 회차를 이어 가는 최소 serialized story loop를 검증합니다.

> When 한 장면의 갈림길에 도달할 때, I want 의미 있는 선택을 하고 그 결과를 다음 회차에서 확인하기를, so I can 이야기를 읽는 사람이 아니라 진행하는 주인공처럼 느낄 수 있다.

## Scope

- synthetic content로 만든 최소 두 회차의 scene/choice/branch loop
- explicit episode boundary와 next-episode hook
- checkpoint, resume와 prior-choice recap
- 선택에 따른 관찰 가능한 후속 장면 차이
- 자유 채팅과 structured story progression의 이해 비교
- informed consent, minimum participant input과 private research retention/deletion
- `proceed`, `narrow`, `fix` 또는 `stop` 결정

## Out Of Scope

- production model inference, prompt pipeline 또는 content generation quality benchmark
- long-term relationship/world-state model
- creator authoring UI
- real account, payment, public publishing 또는 user-generated content
- personal lifelog source 사용

## Acceptance Criteria

- prototype 범위, participant profile, task, success threshold와 stop rule을 실행 전에 고정합니다.
- 사용자가 최소 두 회차에서 scene, choice, branch와 resume을 스스로 진행할 수 있습니다.
- 적어도 하나의 선택이 reference trace에서 후속 scene, state 또는 available choice 중 하나를 바꾸고 사용자가 그 차이를 설명할 수 있습니다.
- 사용자가 자유 대화가 아니라 회차형 이야기 진행이라는 mental model을 이해하는지 evidence로 구분합니다.
- 진행 중단, 잘못된 선택과 resume 실패를 숨기지 않고 관찰·기록합니다.
- production runtime 없이 clickable, scripted 또는 concierge prototype으로 핵심 loop를 검증할 수 있습니다.
- consent, raw observation과 participant input은 public repository에 넣지 않고 access-controlled research storage와 retention/deletion plan을 적용합니다.
- 결과가 POV-027을 `proceed`, `narrow`, `fix` 또는 `stop`으로 결정합니다.

## Verification

- prototype state/branch walkthrough
- participant task completion과 confusion evidence traceability
- episode checkpoint/resume readback
- synthetic-content와 public-repository safety review
- decision and roadmap readback
- `git diff --check`

## Rollback

`fix`이면 관찰된 핵심 confusion만 수정해 같은 decision rule로 다시 검증합니다. `stop`이면 POV-027~029를 열지 않고 POV-024에서 H6 disposition을 기록합니다. prototype artifact와 raw research data는 retention plan에 따라 폐기할 수 있지만 anonymized learning과 decision은 보존합니다.

## Links

- [H6 Epic — POV-024](POV-024-storyworld-follow-on-outcome.md)
- [Previous — POV-025](POV-025-storyworld-reader-demand-and-positioning.md)
- [Next — POV-027](POV-027-persistent-world-state-experience-gate.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
