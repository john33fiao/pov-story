# POV-035 Planned Key Rotation And Retirement Operator

Status: Planned — crash-resumable planned/retire maintenance core implemented; production operator surface absent

Type: Delivery

Roadmap: Auth maintenance follow-up

Depends on: POV-007

## Why

POV-007에서 planned rotation과 verify-only retirement의 storage/filesystem lifecycle은
구현됐지만 production operator가 호출할 수 없습니다. 초기 login flow와 장기 key
maintenance를 분리해 H1 delivery를 막지 않으면서도 90일 cryptoperiod와 verify-only
cleanup을 운영 가능한 경계로 닫아야 합니다.

## What

listener가 닫힌 maintenance mode에서 existing planned/retire transition을 시작하거나
재개하는 production operator command를 연결합니다.

## Scope

- explicit instance root를 받는 planned rotation operator command
- verify-only deadline 뒤 retirement operator command
- existing maintenance lock, actor와 transition outcome 재사용
- no caller-supplied path, KID, key material, timestamp 또는 lifecycle fact
- partial transition의 typed resume와 exact terminal replay
- parser, redaction, contention과 no-mutation negative evidence

## Out Of Scope

- initialization, login/session HTTP runtime
- compromise/loss recovery
- key cryptoperiod 정책 변경
- native Windows auth maintenance enablement
- abrupt power-loss 또는 filesystem별 durability claim

## Acceptance Criteria

- operator command는 auth listener와 동시에 실행되지 않습니다.
- current source와 keyring이 exact precondition을 만족할 때만 transition을 시작합니다.
- 이미 시작된 legal transition은 새 key나 audit를 중복 생성하지 않고 재개합니다.
- unknown, mismatched 또는 unsafe artifact가 있으면 자동 정리하지 않고 fail closed합니다.
- argv, log, error와 Debug에 key material, KID, transition ID 또는 instance root를 노출하지 않습니다.
- planned/retire terminal state 뒤 `AuthRuntime` startup이 exact source와 active keyring을 검증합니다.

## Verification

- production subprocess parser/dispatch tests
- planned/retire normal, replay, contention과 interrupted-resume tests
- listener-open and unsafe-artifact no-mutation tests
- targeted auth tests, repository validation and `git diff --check`

## Rollback

operator command 노출을 제거하되 이미 시작된 legal transition evidence는 삭제하지 않습니다.
재개 가능한 maintenance core와 fail-closed startup을 유지합니다.

## Links

- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-036](POV-036-auth-key-compromise-and-loss-recovery.md)
- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)

