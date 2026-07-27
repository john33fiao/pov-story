# POV-016 Supervised Audio Normalization And Transcription

Status: Planned

Type: Delivery

Roadmap: H2 — Correctable voice recall

Depends on: POV-006, POV-015, POV-033

## Why

전사 성공뿐 아니라 invalid media, timeout, cancellation과 process crash가 source data를 잃거나 orphan process와 intermediate WAV를 남기지 않는 것이 제품 신뢰의 일부입니다.

## What

ProcessSupervisor를 통해 `ffprobe` 검사, `ffmpeg` normalization과 platform-selected
Whisper multilingual provider를 순서대로 수행하고 결과를 immutable initial transcript
revision으로 기록합니다. Windows Python Whisper 실행·격리 계약은 POV-033을 따릅니다.

## Scope

- media probe validation and bounded metadata
- isolated per-job work directory
- audio normalization and multilingual transcription
- platform-selected transcriber adapter behind the existing provider port
- segment/language/confidence-capable result contract
- initial transcript revision and source audio hash
- success, failure, timeout, cancellation and cleanup
- runtime/model artifact provenance

## Out Of Scope

- final high-quality profile selection
- transcript correction UI
- embedding and recall
- speaker diarization guarantee
- cloud transcription

## Acceptance Criteria

- executable과 arguments는 allowlist/array로 전달되며 shell string을 사용하지 않습니다.
- Windows Python Whisper path는 POV-033의 runtime/model provenance와 Job Object
  containment evidence를 통과합니다.
- Korean 기본 후보는 multilingual model이고 `base.en`을 기본값으로 사용하지 않습니다.
- invalid input, non-zero exit, timeout와 cancellation이 구분된 job state로 기록됩니다.
- success와 모든 failure path 뒤 orphan process, unbounded output와 intermediate WAV가 남지 않습니다.
- initial transcript revision은 audio/source hash, backend, runtime build, model artifact revision/hash와 elapsed time을 보존합니다.
- retry가 동일 input의 transcript revision과 job result를 중복 생성하지 않습니다.

## Verification

- synthetic valid/invalid audio fixtures only
- probe/normalize/transcribe success and failure integration tests
- timeout/cancel/forced-kill cleanup inspection
- provenance and idempotency assertions
- actual repository validation commands and `git diff --check`

## Rollback

transcription capability를 비활성화하고 media/job을 실패 또는 pending 상태로 보존합니다. temporary audio는 retention policy를 계속 따르며 silent indefinite retention으로 rollback하지 않습니다.

## Links

- [POV-002 Epic](POV-002-voice-lifelog-round-trip.md)
- [Roadmap](../WBS.md)
- [POV-006](../deps/POV-006-provider-ports-and-safe-process-supervisor.md)
- [POV-015](POV-015-authenticated-idempotent-voice-intake.md)
- [POV-033](POV-033-windows-python-whisper-turbo-provider.md)
