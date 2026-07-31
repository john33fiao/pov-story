# POV-039 Repair Job Status Browser Evidence Fixture

Status: Planned — opened by POV-013 `fix`

Type: Corrective test

Roadmap: H1 — Trustworthy text capture

Depends on: POV-011, POV-012

Blocks: POV-013

## Why

POV-013의 exact target `70ad66146a7f47dde3157ed0089ef8316e81e8ee`에서
`npm --prefix web run test:browser`가 실패했습니다. Production parser는 owner-scoped status
linkage인 `conversation_id`와 `source_event_id`를 필수로 검증하지만 Playwright의
`statusEvent` fixture가 두 필드를 만들지 않아 client가 frame을 거부하고 `상태 다시 연결
중`에 머뭅니다.

## Scope

- Playwright job-status fixture를 current API event schema와 일치
- refresh handoff, reconnect cursor와 reload assertions 유지
- bearer-token URL/storage/cache non-persistence assertion 유지

## Out Of Scope

- production SSE/API schema 변경
- parser validation 완화
- auth, queue, generation 또는 UI 동작 변경
- POV-013/038의 실제 installed-browser evidence 실행

## Acceptance Criteria

- fixture가 canonical UUID v4 `conversation_id`와 `source_event_id`를 포함합니다.
- `npm --prefix web run test:browser`가 current Chromium project에서 PASS합니다.
- malformed linkage를 거부하는 unit regression과 token non-persistence assertion이 그대로
  PASS합니다.
- production source와 migration에는 변경이 없습니다.

## Verification

- `npm --prefix web run test:browser`
- `npm --prefix web run test`
- frontend format, lint, typecheck and production build
- `git diff --check` and relative Markdown-link check

## Rollback

Test-only fixture 변경을 되돌리면 production behavior는 바뀌지 않지만 POV-013은 다시
`fix` 상태로 돌아갑니다.

## Links

- [POV-011](../deps/POV-011-authenticated-replayable-job-status-stream.md)
- [POV-012](POV-012-loopback-llm-text-round-trip.md)
- [POV-013](POV-013-conversation-core-offline-evidence-gate.md)
