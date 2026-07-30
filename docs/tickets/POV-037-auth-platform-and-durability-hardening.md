# POV-037 Auth Platform And Durability Hardening

Status: Planned — evidence backlog; not an initial H1 text-capture activation gate

Type: Hardening evidence

Roadmap: Auth hardening follow-up

Depends on: POV-007

## Why

POV-007의 synthetic fault injection과 supported-Unix initialization smoke는 initial local auth
delivery를 검증하지만 모든 OS, terminal race, abrupt crash와 filesystem의 물리적
durability를 증명하지 않습니다. 이 residual을 POV-007 완료 조건에 무기한 누적하지 않고,
구체적인 platform/release claim 전에 별도 evidence gate로 관리합니다.

## What

인증 구현의 platform별 terminal behavior, reference-device KDF 비용과 실제
crash/filesystem durability를 측정하고 남은 same-UID race를 완화하거나 명시적으로
수용합니다.

## Scope

- claim할 Linux/macOS별 production PTY signal restore/retermination과 exact success
- output fault, process-group race와 maintenance-lock contention snapshot
- reference device의 exact Argon2id profile latency와 memory evidence
- abrupt process termination과 selected filesystem durability experiment
- preparation/source predicate 직후 same-UID ABA의 mitigation 또는 accepted residual
- platform별 supported/unsupported matrix와 reproducible commands

## Out Of Scope

- POV-007 local login/session feature 확장
- installed-browser UI/cookie/storage evidence
- native Windows auth maintenance/runtime enablement
- same OS account의 arbitrary malicious process를 완전히 방어한다는 주장
- copy-on-write, journal, snapshot에서 physical secure erase 보장

## Activation Rule

- 초기 H1 text capture는 이 ticket을 기다리지 않습니다.
- 특정 Linux/macOS production 지원, filesystem durability 또는 reference-device performance를
  release claim으로 올리기 전에 해당 행의 evidence를 완료합니다.
- Native Windows H1 dogfood가 선택되면 이 ticket에 성공 stub을 추가하지 않고 별도
  auth maintenance/runtime delivery ticket을 만듭니다.

## Acceptance Criteria

- 각 platform claim은 exact OS/filesystem/runtime과 재현 명령을 기록합니다.
- unavailable platform이나 실험은 PASS로 기록하지 않습니다.
- crash 뒤 legal terminal/resume state와 listener fail-closed behavior를 구분합니다.
- Argon2 측정은 exact current PHC parameter와 reference-device 조건을 보존합니다.
- 남은 ABA 또는 physical durability 한계는 완화 여부와 residual threat를 명시합니다.

## Verification

- platform PTY harness and terminal restoration evidence
- reference-device Argon2 benchmark
- abrupt-kill and filesystem durability experiment
- maintenance lock contention and artifact readback
- repository validation applicable to changed harness/code

## Rollback

새 hardening code나 harness를 비활성화해도 POV-007의 fail-closed startup과 기존 synthetic
regression suite는 유지합니다. 측정 결과는 삭제하지 않고 platform claim을 낮춥니다.

## Links

- [POV-007](../deps/POV-007-local-login-refresh-and-session-revoke.md)
- [POV-035](POV-035-planned-key-rotation-and-retirement-operator.md)
- [POV-036](POV-036-auth-key-compromise-and-loss-recovery.md)
- [POV-034](../deps/POV-034-restore-windows-workspace-validation-baseline.md)
- [ADR-0004](../decisions/0004-local-authentication-and-session-security-contract.md)

