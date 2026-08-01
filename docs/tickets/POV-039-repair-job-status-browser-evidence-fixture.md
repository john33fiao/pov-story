# POV-039 Repair Job Status Browser Evidence Fixture

Status: Completed — 2026-08-01; Chromium, unit and frontend baseline PASS

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

## Evidence Result

Completed on 2026-08-01 with a test-only fixture repair.

- `web/e2e/job-events.spec.ts`의 `statusEvent`에 canonical UUID v4
  `conversation_id`와 `source_event_id`를 추가했습니다. Production parser, SSE/API schema,
  migration, auth, queue, generation과 UI source는 변경하지 않았습니다.
- `npm --prefix web run test:browser`는 sandbox의 loopback bind `EPERM` 뒤 같은 명령을 host
  경계에서 재실행해 current Chromium project `1/1` PASS했습니다. 기존 refresh handoff,
  reconnect cursor, reload와 bearer-token URL/storage/cache non-persistence assertion은 그대로
  실행됐습니다.
- `npm --prefix web run test`는 `2` files와 `13/13` tests가 PASS했습니다. Owner-scoped
  conversation linkage가 빠진 malformed event를 거부하는 unit regression은 변경하지
  않았습니다.
- Frontend format, lint, typecheck와 production build, `git diff --check`, changed Markdown
  relative-link check가 PASS했습니다. Playwright가 만든 ignored
  `test-results/.last-run.json` 때문에 첫 format check가 실패했지만 generated file을 제거한
  뒤 같은 명령이 PASS했고 tracked artifact로 남지 않았습니다.
- 이 결과는 POV-039만 완료합니다. POV-013의 exact `70ad661` E04/E08 FAIL은 역사적 실행
  결과로 유지합니다. 후속 POV-040은 완료됐지만 POV-013 전체 재실행과 E10/E11
  target-Chrome evidence는 남아 있습니다.

## Rollback

Test-only fixture 변경을 되돌리면 production behavior는 바뀌지 않지만 POV-013은 다시
`fix` 상태로 돌아갑니다.

## Links

- [POV-011](../deps/POV-011-authenticated-replayable-job-status-stream.md)
- [POV-012](POV-012-loopback-llm-text-round-trip.md)
- [POV-013](POV-013-conversation-core-offline-evidence-gate.md)
