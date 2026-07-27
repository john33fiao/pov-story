# POV-001 Local Offline Walking Skeleton

Status: Completed

Completed: 2026-07-25

Type: Delivery

Roadmap: H0 — Reproducible local boundary

## Why

이후 auth, conversation, upload와 local inference를 올리기 전에 production runtime, same-origin과 offline 경계를 실제 build와 smoke test로 검증해야 합니다. 문서뿐인 기술 기준선을 가장 작은 실행 가능한 slice로 바꿉니다.

## What

Rust service가 React/Vite production shell과 최소 health API를 `127.0.0.1:8080` same-origin으로 제공하는 가장 작은 실행 가능한 vertical slice를 만듭니다.

## Scope

- Rust workspace와 Axum application scaffold
- React, TypeScript, Vite application scaffold
- production frontend build artifact를 Rust가 제공
- `GET /api/health` 같은 data/model-independent health endpoint
- default loopback binding
- 외부 CDN 없이 offline page load
- 실제 install, format, lint, typecheck, build, test, smoke 명령 문서화
- generated output과 local config ignore 확인
- README, `AGENTS.md`, RTD validation section 갱신

## Out Of Scope

- authentication, JWT, refresh token
- Conversation/Knowledge/Calendar/Embedding schema
- Discord adapter
- SSE job state
- audio upload, Blob, transcription, embedding
- Cloudflare deployment
- model download or execution
- polished product UI

## Acceptance Criteria

- clean checkout에서 문서화된 toolchain과 install command로 dependencies를 준비할 수 있습니다.
- 문서화된 build/test command가 성공합니다.
- production mode에서 Rust process 하나가 frontend shell과 health endpoint를 같은 origin에서 제공합니다.
- 기본 bind address가 `127.0.0.1`이며 명시 없이 LAN 전체에 노출되지 않습니다.
- network를 끊어도 shell에 필요한 JavaScript, CSS, font를 외부에서 요청하지 않습니다.
- health endpoint는 DB, model, personal data에 접근하지 않습니다.
- build artifact, dependency directory, local config가 Git status에 나타나지 않습니다.
- runtime/version 선택과 실제 commands가 README, `AGENTS.md`, RTD에 동기화됩니다.

## Implementation Notes

- framework version과 package manager를 이 문서에서 미리 발명하지 않습니다. scaffold 시 공식 지원 상태를 확인하고 manifest/lockfile로 고정합니다.
- frontend dev server는 개발 도구일 수 있지만 production runtime은 Rust가 제공합니다.
- embedding 또는 asset packaging 방식은 가장 작은 검증 가능한 방법을 선택하고 premature abstraction을 피합니다.

## Verification

- `npm --prefix web ci`
- `npm --prefix web run format:check`
- `npm --prefix web run lint`
- `npm --prefix web run typecheck`
- `npm --prefix web run build`
- `cargo fmt --all -- --check`
- `cargo check --locked --workspace --all-targets`
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `cargo test --locked --workspace --all-targets`
- `cargo build --locked --workspace --release`
- `sh scripts/smoke.sh`
- production browser shell, console and same-origin resource inspection
- `git diff --check`

## Completion Evidence

- Rust `1.95.0`, Node.js `26.4.0`과 npm `11.17.0`을 toolchain files와 manifests에 고정했습니다.
- Axum `0.8.9` application은 default `127.0.0.1:8080`에서 `GET /api/health`와 Vite production asset을 제공합니다.
- release build는 React `19.2.8`과 Vite `8.1.5` output을 binary에 포함하며 unknown `/api/*`, missing asset과 traversal-shaped path를 404로 분리합니다.
- integration test 8개가 health body/header, loopback address, frontend shell/CSP, GET/HEAD method boundary, API fallback, emitted JavaScript header와 encoded asset path boundary를 검증합니다.
- release process smoke가 shell과 health의 same-origin 응답을 확인했습니다.
- browser inspection에서 console warning/error 0, horizontal overflow 0, 외부 request 0을 확인했습니다. 로드된 JavaScript와 CSS는 모두 `127.0.0.1:8080` same-origin이었습니다.
- `target/`, `web/node_modules/`, `web/dist/`와 local configuration은 ignore되어 public changed set에 포함되지 않습니다.

## Rollback

walking skeleton 관련 manifests/source/config만 제거하고 pre-implementation docs 상태로 돌아갈 수 있어야 합니다. architecture baseline을 바꾸는 선택이 생기면 단순 rollback 대신 새 ADR을 작성합니다.

## Links

- [Architecture](../ARCHITECTURE.md)
- [Product Strategy](../PRODUCT_STRATEGY.md)
- [TODO](../TODO.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [ADR-0001](../decisions/0001-architecture-baseline.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
- [POV-002](../tickets/POV-002-voice-lifelog-round-trip.md)
