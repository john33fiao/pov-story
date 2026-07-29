# POV-036 Auth Key Compromise And Loss Recovery

Status: Planned — ADR contract accepted; persisted compromise/loss transition과 production operator 미구현

Type: Delivery

Roadmap: Auth recovery follow-up

Depends on: POV-007, POV-035

## Why

signing key compromise와 loss는 normal rotation이 아닙니다. session/credential invalidation,
recovery-code authorization과 replacement key publication을 하나의 fail-closed recovery
contract로 연결하지 않으면 operator 편의를 위해 인증을 우회하거나 mixed state에서
listener를 열 위험이 있습니다.

## What

ADR-0004의 compromise/loss source transition, crash-resumable secret-filesystem lifecycle과
controlling-TTY production operator를 구현합니다.

## Scope

- strict compromise/loss metadata와 source expectation
- saved recovery-code authorized operator flow
- replacement key와 applicable recovery credential preparation
- credential version 증가, session/family revoke와 outcome invalidation
- source CAS, key install, final lifecycle CAS와 deletion-only cleanup
- response-loss, retry와 partial-transition recovery
- terminal state의 listener-ready verification

## Out Of Scope

- support override, email/SMS reset 또는 synthetic production owner context
- password와 saved recovery code를 모두 잃은 bypass
- remote recovery endpoint
- planned rotation/retirement
- physical secure erase 보장

## Acceptance Criteria

- compromise/loss command는 listener가 닫히고 maintenance lock을 소유한 상태에서만 실행됩니다.
- recovery code 검증 전에는 durable auth mutation이나 replacement secret publication이 없습니다.
- successful source transaction은 credential version, applicable verifier, session revoke와 audit를 원자적으로 묶습니다.
- commit uncertainty에서 token, cookie 또는 success를 발급하지 않습니다.
- legal partial transition은 idempotent하게 재개하고 unknown/mismatched evidence는 보존한 채 fail closed합니다.
- recovery 뒤 stale access/refresh token과 이전 signing key는 허용된 overlap 없이 거부됩니다.

## Verification

- compromise/loss metadata corruption and redaction tests
- source-CAS, response-loss and recovery-code throttle tests
- phase별 interrupted-resume and replay tests
- stale session/key rejection and listener-ready startup tests
- production operator TTY negative tests, repository validation and `git diff --check`

## Rollback

operator entrypoint를 닫아 신규 recovery 시작을 막되 이미 시작된 legal transition evidence는
삭제하지 않습니다. Listener는 terminal recovery 전까지 fail closed 상태를 유지합니다.

## Links

- [POV-007](POV-007-local-login-refresh-and-session-revoke.md)
- [POV-035](POV-035-planned-key-rotation-and-retirement-operator.md)
- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)

