# POV-011 Authenticated Replayable Job Status Stream

Status: Planned

Type: Delivery

Roadmap: H1 — Trustworthy text capture

Depends on: POV-009, POV-010

## Why

긴 local 작업은 page refresh, token expiry와 연결 중단 뒤에도 상태를 잃지 않아야 합니다. query-string token이나 cache된 status로 이를 해결하면 개인정보 경계가 약해집니다.

## What

Bearer access token을 사용하는 fetch-streaming SSE와 durable status cursor를 구현합니다. client는 access token 만료 전에 stream을 닫고 refresh 뒤 마지막 cursor부터 owner-scoped 상태를 재개합니다.

## Scope

- durable job status event and monotonically ordered cursor
- Authorization header 기반 fetch streaming
- reconnect, resume and duplicate suppression
- token refresh handoff
- owner scope, cache-control and redaction
- bounded heartbeat and disconnect cleanup

## Out Of Scope

- native EventSource query token
- WebSocket
- push notification
- Cloudflare deployment tuning
- multi-device fanout

## Acceptance Criteria

- status stream URL, query, browser storage와 log에 access/refresh token이 남지 않습니다.
- 다른 owner의 job status와 cursor를 읽을 수 없습니다.
- access token 만료 전에 stream이 종료되고 refresh 뒤 마지막 durable cursor에서 재개됩니다.
- reconnect 뒤 terminal/progress event가 유실되거나 사용자에게 중복 적용되지 않습니다.
- API, SSE와 auth response가 browser/service-worker/proxy cache 대상이 아닙니다.
- client disconnect와 server cancel 뒤 stream task나 resource가 누수되지 않습니다.

## Verification

- owner isolation and invalid cursor tests
- expiry/refresh/reconnect browser test
- duplicate, gap and terminal event replay tests
- cache header and token leakage inspection
- actual repository validation commands and `git diff --check`

## Rollback

stream endpoint를 끄고 durable status를 polling으로 읽는 임시 fallback을 사용할 수 있어야 합니다. status event와 cursor history는 보존합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [POV-009](../deps/POV-009-durable-single-slot-job-queue.md)
- [POV-010](POV-010-minimal-authenticated-local-text-chat.md)
