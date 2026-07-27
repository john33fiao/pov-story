# Reference Provenance

초기 requirements와 architecture baseline은 2026-07-22에 정리된 private Mk4 기획 노트 `라이프로깅 챗봇`을 2026-07-24 repository initialization에서 검토해 파생했습니다.

2026-07-25 product-direction review에서는 사용자가 명시적으로 제공한 `라이프로깅 챗봇`과 별도 private 기획 노트 `포브스토리 - 사이드 프로젝트`를 함께 대조했습니다. 초기 review는 AI storyworld를 별도 product hypothesis로 해석했으나, 사용자가 같은 날 이를 local-first lifelogging 기반 이후의 후속 제품 방향으로 명시적으로 정정했습니다. 현재 distilled decision은 [Product Strategy](../PRODUCT_STRATEGY.md)와 [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)을 따르며, [ADR-0002](../decisions/0002-product-direction-and-repository-identity.md)는 superseded history로만 보존합니다.

private 원문은 이 public repository에 포함하지 않습니다. 원문의 frontmatter, personal vault path, wikilinks, 실제 기록 데이터도 복사하지 않습니다. 구현 에이전트는 원문 접근을 전제로 하지 않고 다음 public active docs를 사용해야 합니다.

- `README.md`
- `docs/PRODUCT_STRATEGY.md`
- `docs/ARCHITECTURE.md`
- `docs/TODO.md`
- `docs/WBS.md`
- `docs/OPEN_QUESTIONS.md`
- `docs/decisions/`
- `docs/tickets/`

향후 private 원문과 요구사항을 다시 맞추는 작업은 사용자가 원문을 명시적으로 제공할 때 수행하고, 변경 결과를 active docs와 ADR에 반영합니다.

외부 기술 문서나 source artifact를 `docs/refs/`에 추가할 때는 provenance, license, snapshot/version, public redistribution 가능 여부를 먼저 확인합니다. secret, personal data, raw audio, transcript, local DB, model weight는 reference material로 커밋하지 않습니다.
