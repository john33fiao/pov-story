# POV-033 Windows Python Whisper Turbo Provider

Status: Planned — POV-034 platform compile baseline completed; implementation not started

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-006, [POV-034 completed](../deps/POV-034-restore-windows-workspace-validation-baseline.md)

## Why

Windows reference 환경에서는 Python OpenAI Whisper와 `large-v3-turbo.pt` 조합이 CUDA를
사용하며, 별도 whisper.cpp GGML artifact보다 기존 설치·운영 경로와 호환성이 높습니다.
그러나 현재 `ProcessSupervisor`는 non-Unix에서 fail closed하므로 이 경로를 ad hoc
script나 shell로 연결하면 process cleanup, executable trust와 artifact provenance
계약을 우회하게 됩니다.

## User Outcome

Windows 사용자는 인터넷이나 cloud transcription 없이 설치된 Python Whisper turbo
runtime으로 음성을 전사할 수 있고, 실패·취소·timeout 뒤에도 원본 접수 상태와 local
process 안전 경계를 신뢰할 수 있습니다.

## What

감사 가능한 Windows one-shot process containment를 `pov-platform` 경계에 추가하고,
Python OpenAI Whisper adapter를 기존 `Transcriber` port 뒤에 연결합니다.
`large-v3-turbo`는 Windows compatibility와 resource evidence를 수집할 후보이며,
versioned 품질 gate 전에는 release default나 cross-platform invariant가 아닙니다.

## Delivery Units

1. Windows executable/work-root trust와 Job Object 기반 process-tree containment
2. Python Whisper turbo adapter, runtime/model provenance와 Windows reference evidence

각 delivery unit은 현재 provider/process contract를 유지하는 독립 diff와 실제 Windows
검증 증거를 가져야 합니다.

## Scope

- `pov-platform`에 격리된 최소 Windows process·filesystem binding
- Job Object kill-on-close, suspended child의 user code 실행 전 assignment와 breakaway
  방지
- trusted Python interpreter와 app-owned wrapper의 absolute path, identity와 actual-byte
  검증
- Python/Whisper/Torch/CUDA distribution build와 `.pt` model revision·SHA-256을
  포함하는 runtime manifest
- shell 없는 fixed argv, 최소 고정 environment와 owner-only attempt directory
- attempt-local normalized audio input과 bounded structured transcript output
- CUDA capability 확인과 device/backend provenance
- missing/corrupt/drifted runtime·model, CUDA unavailable, non-zero exit, timeout,
  cancellation, output overflow와 cleanup failure의 typed mapping
- synthetic multilingual fixture와 Windows reference-device latency·memory evidence

## Out Of Scope

- model, Python 또는 package의 자동 다운로드·업데이트
- model weight, 실제 음성이나 local cache path의 repository 저장
- 측정되지 않은 silent CUDA-to-CPU fallback
- macOS/Linux Whisper backend 교체
- final quality profile 또는 release-default artifact 확정
- media upload, transcript persistence와 correction UI
- speaker diarization guarantee
- cloud transcription

## Safety Contract

- Python executable, wrapper, required distribution과 model은 PATH, user-selected module
  search path 또는 network lookup으로 발견하지 않습니다.
- runtime request는 raw 사용자 filename, transcript, model path, cwd, environment 또는
  shell string을 주입하지 않습니다.
- Windows trust 검증은 reparse point, unexpected hard link, writable ancestor, ACL/owner와
  file identity drift를 거부하고 실제 구현에 필요한 unsafe FFI는 `pov-platform` 안에만
  둡니다.
- direct child와 descendant는 하나의 Job Object에 포함하며 success, failure, timeout,
  cancellation, caller abort와 supervisor 종료에서 더 이상 실행되지 않음을 확인합니다.
- process-tree 종료나 attempt cleanup을 확인할 수 없으면 supervisor를 poison해 재시작
  전 후속 attempt를 거부합니다.
- transcript와 낮은 entropy의 input digest는 일반 log나 telemetry에 출력하지 않습니다.
- CUDA가 없거나 검증된 resource profile과 맞지 않으면 자동으로 장시간 CPU 작업을
  시작하지 않고 명시적 unavailable 또는 policy 결과로 닫습니다.

## Acceptance Criteria

- Windows에서 current `ProcessSupervisor` contract와 동등한 executable/work-root trust,
  bounded output, timeout, cancellation과 process-tree cleanup evidence가 통과합니다.
- synthetic Korean audio를 `large-v3-turbo` 후보로 전사하고 backend,
  Python/Whisper/Torch/CUDA runtime build, model revision/hash, input hash, CUDA device와
  elapsed time을 보존합니다.
- interpreter, wrapper/package 또는 model bytes가 바뀌거나 누락되면 process를 시작하지
  않거나 typed failure로 닫고 source mutation을 일으키지 않습니다.
- invalid audio, Python import failure, CUDA unavailable, non-zero exit, timeout,
  cancellation, output overflow와 forced cleanup을 서로 구분합니다.
- success와 모든 terminal failure 뒤 child/descendant process와 intermediate audio,
  transcript output 및 attempt directory가 남지 않습니다.
- adapter는 기존 `Transcriber` port를 사용하며 POV-016이 platform backend를 선택해도
  domain contract나 source authority를 바꾸지 않습니다.
- model이 이미 provision된 상태에서는 inference 중 인터넷 연결이 필요하지 않습니다.
- model 후보를 release default로 만들기 전 POV-021에서 versioned Korean quality,
  latency, peak memory와 rollback threshold를 평가합니다.

## Verification

- Windows executable path/reparse point/ACL/identity/hash drift negative tests
- Job Object direct-child/descendant success, non-zero, timeout, cancel, caller-abort와
  kill-on-close tests
- synthetic valid/invalid audio와 corrupt/missing model integration tests
- CUDA available/unavailable 및 금지된 implicit CPU fallback tests
- structured output bound, transcript redaction와 runtime/model provenance assertions
- actual Windows reference-device latency/peak-memory probe
- repository 문서 링크 readback, actual validation commands와 `git diff --check`

## Rollback

Windows Python Whisper capability를 비활성화하고 `Transcriber`를 unavailable로 유지합니다.
POV-016은 media/job을 failed 또는 pending 상태로 보존하며 source intake를 되돌리거나
temporary audio retention을 무기한 연장하지 않습니다. 다른 platform backend와
deterministic fake provider는 영향을 받지 않습니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [POV-006](../deps/POV-006-provider-ports-and-safe-process-supervisor.md)
- [POV-034](../deps/POV-034-restore-windows-workspace-validation-baseline.md)
- [POV-016](POV-016-supervised-audio-normalization-and-transcription.md)
- [POV-021](POV-021-voice-round-trip-evidence-gate.md)
- [Architecture](../ARCHITECTURE.md)
- [Roadmap](../WBS.md)
- [Open Questions](../OPEN_QUESTIONS.md)
