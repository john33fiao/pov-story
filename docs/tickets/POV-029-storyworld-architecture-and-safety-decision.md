# POV-029 Storyworld Architecture And Safety Decision

Status: Gated

Type: Decision gate

Roadmap: H6 — Persistent playable story continuity

Depends on: POV-025, POV-026, POV-027 and POV-028 each `proceed` or accepted `narrow`

## Why

storyworld production은 reader/creator roles, persistent state, generation cost, user-generated content와 결제를 포함할 수 있어 현재 single-owner local lifelog architecture를 자동 확장할 수 없습니다. evidence에 맞는 bounded context와 safety/operations 경계를 결정한 뒤에만 implementation investment를 허용해야 합니다.

## What

POV-025~028의 evidence를 종합해 H6를 `proceed`, `narrow`, `defer` 또는 `stop`으로 결정합니다. 진행할 경우 account, data, runtime, safety, rights, cost와 commerce 경계를 새 ADR과 test/threat matrix로 확정합니다.

> When storyworld production 투자를 결정할 때, I want 검증된 reader/creator evidence와 명시적인 data·safety·cost 경계를, so I can 개인 기록의 신뢰를 훼손하지 않고 운영 가능한 범위만 구현할 수 있다.

## Scope

- reader, creator, operator role과 authorization boundary
- lifelogging과 storyworld의 account, bounded context, source store와 derivative 경계
- personal lifelog opt-in, purpose limitation, isolation, revocation, export, deletion과 retention
- episode, branch, relationship, world state와 ending revision/ownership
- local, cloud 또는 hybrid inference와 model/provider boundary
- provider retention, secondary use, training/fine-tuning과 data deletion contract
- concurrency, quota, generation budget, latency와 failure/cancel/retry behavior
- local/remote ingress, cache, logging, backup와 incident boundary
- moderation, age suitability, abuse, copyright, attribution, takedown과 appeal
- creator publishing, versioning, payment, refund와 settlement 범위
- migration, rollback와 production backlog entry criteria

## Out Of Scope

- architecture decision 전 production code, schema 또는 infrastructure
- demand evidence 없이 cloud scale이나 marketplace를 기본값으로 채택
- private lifelog를 default story context로 사용
- 미확정 법률 해석을 제품 보장으로 표현
- payment provider, model 또는 vendor 계약 체결

## Acceptance Criteria

- POV-025~028의 결정, evidence quality, contradiction과 residual risk를 추적 가능한 summary로 검토합니다.
- upstream `pivot` 또는 `stop`이면 이 ticket을 열지 않고 POV-024에서 H6 disposition과 재검토 조건을 기록합니다.
- upstream evidence가 통과했어도 architecture, safety, rights 또는 cost evidence가 부족하면 이유와 재검토 조건을 가진 `defer` 또는 `stop` 결정을 허용합니다.
- 진행할 경우 accepted ADR이 lifelogging과 storyworld의 account, authorization, source/derivative, retention, export/delete와 backup 경계를 결정합니다.
- personal lifelog 사용은 default-off이며 명시적 opt-in, 목적 제한, 격리, 철회와 삭제 전파를 결정하기 전에는 허용하지 않습니다.
- personal lifelog와 story content의 provider retention, secondary use와 training/fine-tuning은 default-deny로 두고, 예외가 있다면 별도 명시적 동의, deletion과 audit contract를 결정합니다.
- local/cloud inference, concurrency, quota, ingress, cache/log exposure와 provider failure에 대한 threat/test matrix가 있습니다.
- moderation, age, copyright, attribution, takedown, creator ownership, payment/refund/settlement의 포함·제외 범위와 owner가 정해집니다.
- cost envelope, abuse limit, rollout, incident response와 rollback trigger가 후보가 아니라 review 가능한 contract로 기록됩니다.
- accepted `proceed` 또는 `narrow` decision 뒤에만 storyworld production epic과 implementation tickets를 작성합니다.

## Verification

- architecture ADR review against ADR-0001 and ADR-0003
- data-flow, trust-boundary와 abuse-case walkthrough
- privacy, retention, export/delete와 consent review
- role/authorization and creator-rights matrix review
- cost, failure, cancel/retry와 rollback scenario review
- ticket entry-gate and documentation readback
- `git diff --check`

## Rollback

implementation 전에는 decision ADR을 새 ADR로 supersede할 수 있습니다. implementation 뒤에는 data migration, user consent, published world/version, creator rights, payment와 deletion 영향을 평가하는 migration/rollback plan 없이 경계를 되돌리지 않습니다. `defer` 또는 `stop`이면 current lifelogging product와 H0~H5를 계속 운영합니다.

## Links

- [H6 Epic — POV-024](POV-024-storyworld-follow-on-outcome.md)
- [Reader Gate — POV-025](POV-025-storyworld-reader-demand-and-positioning.md)
- [Story Loop — POV-026](POV-026-serialized-story-loop-prototype.md)
- [Continuity Gate — POV-027](POV-027-persistent-world-state-experience-gate.md)
- [Creator Gate — POV-028](POV-028-creator-authoring-and-monetization-validation.md)
- [Architecture](../ARCHITECTURE.md)
- [Open Questions](../OPEN_QUESTIONS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
