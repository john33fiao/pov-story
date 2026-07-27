# POV-013 Conversation Core Offline Evidence Gate

Status: Planned

Type: Evidence gate

Roadmap: H1 — Trustworthy text capture

Depends on: POV-004 through POV-012

## Why

voice upload와 transcription 복잡도를 추가하기 전에 auth, durable source, single-slot queue, local Web Chat과 failure recovery가 실제로 함께 동작한다는 증거가 필요합니다.

## What

clean checkout, offline text capture, owner isolation, idempotent retry, token refresh, status reconnect와 provider crash를 하나의 versioned evidence pack으로 검증하고 H2 진입을 `proceed`, `fix` 또는 `stop`으로 결정합니다.

## Scope

- documented clean setup and build
- local login, capture, job and assistant round trip
- internet/external-app-off regression
- owner spoofing and cross-owner negative cases
- retry, lease expiry, token refresh and stream reconnect
- provider crash/cancel/timeout cleanup
- result summary, blocker and residual risk

## Out Of Scope

- voice/audio
- model quality comparison
- Knowledge or Calendar
- Cloudflare and remote browser
- production personal data

## Acceptance Criteria

- POV-001과 POV-004~012의 executable acceptance evidence가 실제 command/result로 연결됩니다.
- local core flow는 internet, Discord, Obsidian, Calendar와 MCP 없이 완료됩니다.
- cross-owner exposure, duplicate source/job과 simultaneous execution-slot occupancy가 없습니다.
- refresh/reconnect와 process failure 뒤 durable source와 terminal state가 보존됩니다.
- unrun slow/conditional check는 PASS로 표시하지 않고 blocker와 residual risk를 기록합니다.
- H2 진입 결정과 실패 시 열어야 할 좁은 corrective ticket이 명시됩니다.

## Verification

- repository-documented fast validation
- offline browser end-to-end
- auth/retry/stream/process failure integration suite
- staged secret, personal-data and generated-artifact review
- `git diff --check`

## Rollback

gate가 실패하면 voice ticket을 Ready로 바꾸지 않습니다. Conversation Core data를 삭제하지 않고 failed boundary만 좁은 ticket으로 수정합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Roadmap](../WBS.md)
- [POV-002](POV-002-voice-lifelog-round-trip.md)
- [POV-012](POV-012-loopback-llm-text-round-trip.md)
- [POV-022](POV-022-first-segment-and-voice-wedge-discovery-gate.md)
