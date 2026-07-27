# POV-003 Product Direction And Outcome Roadmap

Status: Completed

Type: Documentation

Completed: 2026-07-25

## Why

두 private 기획 노트가 서로 다른 제품을 같은 이름으로 설명하고 있어, 현재 저장소의 제품 정체성과 구현 우선순위를 명시적으로 고정해야 합니다. 제품 방향, outcome 로드맵, 실행 티켓이 한 기준으로 연결되어야 첫 구현이 기능 목록이 아니라 검증할 사용자 가치에 맞춰집니다.

## What

사용자가 명시적으로 제공한 private 기획 노트와 현재 저장소의 accepted 문서를 대조해 제품 전략을 작성합니다. 선택한 방향을 ADR로 남기고, 기존 WBS를 outcome 중심 로드맵과 실행 인덱스로 개편하며, 첫 사용자 가치 검증까지의 backlog를 WWA 형식으로 구체화합니다.

## Scope

- 제품 방향, 첫 사용자 세그먼트, JTBD, 가치 제안, trade-off, 지표와 핵심 가설
- 제품 정체성 선택을 기록하는 ADR
- outcome, 검증 신호, 순서와 진입 조건이 있는 로드맵
- 기존 `POV-001`과 `POV-002`를 보존한 근접 실행 티켓
- README, Architecture, TODO, WBS, provenance와 local agent source order 동기화

## Out Of Scope

- 애플리케이션 코드, runtime manifest, schema 또는 test 구현
- 외부 시장 수치나 경쟁사 현황의 현재성 조사
- AI 스토리월드 또는 캐릭터 채팅 제품 구현
- 모델, quantization, 인증 암호, Blob 암호화, 라이선스의 미결정값 확정
- commit, push 또는 pull request

## Acceptance Criteria

- 저장소가 구현할 단일 제품과 구현하지 않을 별도 제품 가설이 명확히 구분됩니다.
- Product Strategy Canvas의 9개 영역, North Star, 현재 OMTM, 핵심 가설과 저비용 검증이 문서화됩니다.
- 로드맵의 각 근접 horizon은 사용자 outcome, 성공 증거, 의존성과 티켓을 가집니다.
- `POV-002`의 voice lifelog epic은 review 가능한 child ticket으로 분해됩니다.
- 각 새 backlog item은 Why, What, Acceptance Criteria, 검증과 rollback을 포함합니다.
- private 노트의 본문, 절대 경로, wikilink, 개인 데이터가 public 문서에 복사되지 않습니다.
- README, TODO, WBS, Architecture, ADR, ticket과 provenance 사이의 링크와 상태가 일치합니다.

## Verification

- 모든 변경 파일 재읽기
- Markdown 상대 링크와 ticket ID 중복 검사
- private absolute path, secret, 개인 기록, 생성 artifact 유입 검사
- `git diff --check`

## Completion Evidence

- Product Strategy Canvas 9개 영역, North Star, OMTM, 핵심 가설과 저비용 검증을 작성했습니다.
- ADR-0002로 lifelogging과 별도 storyworld hypothesis를 분리하고 local Web Chat 우선순위를 확정했습니다.
- WBS를 H-1~H5 outcome, success evidence, dependency와 decision gate 중심으로 개편했습니다.
- 기존 POV-001/002를 보존하고 discovery, H0, H1과 POV-002 child backlog를 WWA 형식으로 작성했습니다.
- local Markdown link, ticket ID/section, private path와 `git diff --check` 검사를 통과했습니다.

## Rollback

이 ticket에서 추가하거나 수정한 문서만 이전 상태로 되돌립니다. ADR-0001과 기존 architecture baseline은 이 작업에서 교체하지 않습니다.

## Links

- [README](../../README.md)
- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Architecture](../ARCHITECTURE.md)
- [TODO](../TODO.md)
- [WBS](../WBS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [ADR-0002](../decisions/0002-product-direction-and-repository-identity.md)
- [POV-001](POV-001-local-offline-walking-skeleton.md)
- [POV-002](../tickets/POV-002-voice-lifelog-round-trip.md)
