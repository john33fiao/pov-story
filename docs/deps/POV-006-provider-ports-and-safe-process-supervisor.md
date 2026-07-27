# POV-006 Provider Ports And Safe Process Supervisor

Status: Completed

Completed: 2026-07-25

Type: Delivery

Roadmap: H0 — Reproducible local boundary

Depends on: POV-001, POV-004

## Why

model과 media runtime이 domain logic, shell string 또는 한 vendor에 결합되면 failure와 교체가 source data를 위험하게 만듭니다. 실제 모델을 붙이기 전에 provider와 process safety contract를 검증해야 합니다.

## User Outcome

후속 text와 voice 기능에서 model/media runtime 실패나 조작된 입력이 shell 실행, orphan process, 무제한 pipe output 또는 source-data mutation으로 이어지지 않습니다. 실제 model artifact 없이도 동일한 provider 결과와 실패 경계를 반복 검증할 수 있습니다.

## What

LLM, transcription과 embedding provider port, deterministic fake provider, artifact manifest와 ProcessSupervisor contract를 만듭니다. 장기 실행 inference server와 작업별 media child process의 lifecycle을 구분합니다.

## Delivery Units

1. provider port, canonical-byte SHA-256 provenance, deterministic fake와 exact IPv4 loopback endpoint contract
2. trusted executable registry, one-shot ProcessSupervisor, bounded output와 synthetic child integration evidence

각 단위는 독립적으로 RTD Before/After를 통과하고 READY commit으로 닫습니다. 두 단위와 아래 acceptance가 모두 끝나기 전에는 이 ticket을 완료 처리하지 않습니다.

## Scope

- LLM, Transcriber, Embedder port와 synthetic fake
- executable allowlist와 분리된 argument array
- one-shot spawn, timeout, cancel, output limit와 process-group cleanup
- loopback-only long-running server contract
- runtime build, artifact revision/hash, input hash와 elapsed time manifest
- process terminal과 provider failure의 typed mapping

## Out Of Scope

- model download 또는 release-default model 선택
- 실제 Korean quality benchmark
- voice upload, transcript schema 또는 search
- Windows/macOS remote worker protocol
- cloud inference provider
- 실제 long-running provider의 HTTP protocol, readiness identity, restart policy와 inference round trip
- supervisor process 자체의 SIGKILL/power-loss 뒤 descendant containment와 abandoned-attempt recovery
- CPU, memory, fd와 work-directory byte quota

## Safety Contract

- provider provenance의 artifact와 input SHA-256은 caller가 보낸 hash 문자열이 아니라 실제 canonical bytes에서 계산합니다. 낮은 entropy의 input digest는 owner-scoped data이며 일반 log나 telemetry에 출력하지 않습니다.
- process request는 typed executable ID만 사용합니다. registry가 app-owned trust root부터 absolute canonical native executable까지 각 hierarchy component의 identity/mode와 expected SHA-256을 등록 시와 실행 직전에 검증하며 PATH lookup, relative executable, symlink/hard link, writable ancestor, nonnative image와 caller-selected cwd를 거부합니다.
- child는 shell 없이 분리된 argv, cleared environment, null stdin과 supervisor-owned owner-only attempt directory에서 실행합니다. raw 사용자 filename/prompt/transcript는 argv나 environment에 넣지 않고 provider adapter가 만든 안전한 attempt-local basename 또는 protocol body로 전달합니다.
- stdout과 stderr는 동시에 bounded drain하고 child exit와 경합한 최종 drain fault도 terminal result에 합성합니다. timeout, explicit cancellation, output overflow, caller future abort와 자연 parent exit에도 live supervisor가 process group을 종료하고 direct PID/PGID absence를 확인합니다. attempt 삭제는 blocking pool의 bounded cleanup으로 격리합니다. cleanup이 불확실하면 성공으로 매핑하지 않고 현재 process의 supervisor를 poison해 다음 attempt를 거부합니다.
- 현재 Rust process 안의 모든 one-shot supervisor instance가 permit 하나를 공유합니다. crash-recoverable FIFO, lease와 durable system-wide admission은 POV-009가 소유합니다. one-shot child와 long-running server lifecycle은 별도 타입/API이며 실제 server lifecycle은 POV-012에서 이 contract 위에 구현합니다.
- Delivery Unit 2의 executable evidence는 macOS/POSIX process group을 대상으로 합니다. Windows Job Object backend는 해당 target evidence 전까지 fail closed입니다. provider가 process group을 이탈하거나 daemonize하는 동작은 금지합니다.
- `no orphan`은 supervisor가 살아 있는 terminal path에 한정합니다. supervisor 자체 SIGKILL, OS power loss와 restart cleanup은 watchdog 또는 OS containment가 정해질 때까지 conditional residual risk이며 PID-only cleanup으로 추정하지 않습니다.
- exact loopback은 `127.0.0.1:<assigned-port>`만 뜻합니다. provider endpoint는 Axum route, LAN bind 또는 Cloudflare Tunnel route로 노출하지 않습니다. plain loopback에 접근 가능한 같은 OS account의 browser/process는 현재 ADR-0004 trust boundary에 남습니다.

## Acceptance Criteria

- [x] 사용자 입력이나 filename이 shell command string으로 실행되지 않습니다.
- [x] fake child의 success, spawn failure, non-zero/signal exit, timeout, cancellation과 forced cleanup을 재현합니다.
- [x] live supervisor의 terminal path 뒤 direct PID/process group, bounded output와 owned attempt가 남지 않습니다.
- [x] long-running provider endpoint contract는 exact IPv4 loopback-only이며 Axum, LAN 또는 Tunnel route로 직접 노출되지 않습니다.
- [x] provider 결과가 backend, runtime build, artifact revision/hash, input hash와 elapsed time을 포함합니다.
- [x] domain test는 실제 model binary 없이 deterministic fake provider로 실행됩니다.

## Definition Of Done

- provider port는 process implementation type에 의존하지 않고 deterministic fake가 세 capability를 모두 실행합니다.
- one-shot process와 long-running loopback endpoint가 별도 contract로 표현됩니다.
- synthetic process evidence가 literal argv, environment isolation, success, non-zero/signal, timeout, cancellation, dual-stream overflow, descendant cleanup, single-slot serialization과 attempt cleanup을 재현합니다.
- terminal result가 spawn trust/failure, non-zero/signal, timeout, cancellation, output limit와 cleanup failure를 구분합니다.
- 전체 repository validation과 repo-local RTD After가 PASS하고 README, Architecture, TODO, WBS와 ticket 상태가 실제 구현에 맞습니다.

## Verification

- README에 고정된 frontend format/lint/typecheck/build, Rust fmt/check/clippy/test/release와 loopback smoke validation PASS
- `process_supervisor` synthetic self-spawn suite가 literal argv, exact cleared environment, success, spawn/non-zero/signal, timeout/cancel, caller abort, dual-pipe pressure/short overflow, natural-exit descendant, process-local serialization, executable trust drift와 symlink-safe cleanup을 PASS
- provider contract suite가 model-free three-port behavior, actual-byte provenance, redaction과 exact IPv4 loopback rejection을 PASS
- `git diff --check` PASS

## Delivered Evidence

- `pov-core::provider`: process-independent LLM, Transcriber와 Embedder port, canonical-byte SHA-256 provenance, deterministic fake와 exact `127.0.0.1` endpoint type
- `pov-core::process`: typed registry, finite policy, detached lifecycle actor, process-local single permit, bounded dual-pipe capture, typed terminal/cleanup report와 provider error mapping
- `tests/provider_contract.rs`: actual artifact/input digest, deterministic capabilities, redacted debug와 endpoint negative cases
- `tests/process_supervisor.rs`: ignored self-spawn fixtures를 실제 child/process group으로 실행하는 macOS/POSIX integration evidence

## Residual Risks

- same OS account가 verify와 exec 사이 path hierarchy를 바꾸는 작은 TOCTOU window는 app-owned trust root 가정에 남습니다.
- process group을 의도적으로 벗어나는 daemon/`setsid`, supervisor process 또는 Tokio runtime 자체의 abrupt termination과 power loss는 containment하지 않습니다. PID-only restart cleanup으로 추정하지 않습니다.
- CPU, memory, fd와 attempt byte quota는 아직 강제하지 않습니다. actual provider artifact pin/update/rollback과 quality/resource benchmark 전에는 real provider를 활성화하지 않습니다.
- macOS에서 direct child와 process-group evidence를 실행했습니다. Linux는 ELF/process-group implementation을 가지지만 target evidence 전까지 별도 검증이 필요하며 non-Unix는 fail closed입니다.

## Rollback

실제 provider를 비활성화하고 fake provider만으로 core domain을 유지할 수 있어야 합니다. process cleanup이 불확실하면 capability를 fail closed로 끕니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [POV-004](POV-004-core-data-identity-and-store-boundaries.md)
- [POV-012](../tickets/POV-012-loopback-llm-text-round-trip.md)
- [POV-016](../tickets/POV-016-supervised-audio-normalization-and-transcription.md)
