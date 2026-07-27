# POV Story

POV Story는 메모, 음성, 일정, 할 일, 작업일지와 장기 기억을 하나의 대화형 인터페이스에서 다루는 local-first 개인 라이프로깅 앱입니다. 현재 이름은 working title입니다. 회차·선택·관계·세계 상태가 이어지는 AI storyworld는 lifelogging 기반 이후의 H6 후속 방향이며, 현재 MVP나 runtime 범위가 아닙니다.

## 현재 상태

- Rust/Axum process가 React/Vite production shell과 data-independent health API를 `127.0.0.1:8080` same-origin으로 제공합니다.
- owner/source/revision, 네 SQLite lifecycle, safe process supervisor와 POV-008/009 persistence core가 구현되어 있습니다.
- 인증은 schema, credential·key lifecycle과 initialization primitive까지만 구현됐고 production login/JWT/HTTP/runtime wiring은 아직 없습니다. 신규 initialization은 corpus evaluation을 주장하지 않는 persisted sentinel을 사용하며 password blocklist enforcement는 current tree에서 제거됐습니다.
- Windows Rust workspace check/test baseline은 [POV-034](docs/deps/POV-034-restore-windows-workspace-validation-baseline.md)에서 복구됐고 Unix auth maintenance capability는 Windows에서 계속 비활성입니다.
- 실제 lifelog 접수, background dispatcher, provider/model 실행은 활성화되지 않았습니다.

H1 delivery는 [POV-022 discovery gate](docs/tickets/POV-022-first-segment-and-voice-wedge-discovery-gate.md)와 [POV-007 auth delivery](docs/tickets/POV-007-local-login-refresh-and-session-revoke.md)에 gated되어 있습니다.

## 빠른 실행

고정된 개발 기준은 Rust `1.95.0`, Node.js `26.4.0`, npm `11.17.0`입니다. Vite asset을 Rust binary에 포함하므로 frontend를 먼저 build합니다. `.nvmrc`가 Node 기준 버전의 정본이며, 아래 `nvm` 명령은 Unix 계열 shell 기준입니다. Windows PowerShell에서는 nvm-windows 등 호환 version manager로 Node.js `26.4.0`을 선택한 뒤 npm 명령부터 실행합니다.

```bash
nvm install
nvm use
npm --prefix web ci
npm --prefix web run build
cargo run --locked --release -p pov-api
```

다른 terminal에서 health endpoint를 확인합니다.

```bash
curl --fail http://127.0.0.1:8080/api/health
```

## 대표 검증

```bash
npm --prefix web run format:check
npm --prefix web run lint
npm --prefix web run typecheck
npm --prefix web run build
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
sh scripts/smoke.sh
git diff --check
```

변경 영역별 전체 fast/conditional 검증은 해당 ticket과 project workflow를 따릅니다.
[POV-034](docs/deps/POV-034-restore-windows-workspace-validation-baseline.md)는 Windows와 Unix의 platform-gated auth/storage 검증 증거를 함께 보존합니다.
Windows에서 `scripts/smoke.sh`를 실행하려면 Git Bash 또는 WSL처럼 POSIX shell을 제공하는 환경이 필요합니다.

## 문서

- [Product Strategy](docs/PRODUCT_STRATEGY.md): 사용자, 가치, trade-off와 H6 방향
- [Architecture](docs/ARCHITECTURE.md): 현재 구현과 기술·보안 경계
- [Live TODO](docs/TODO.md): 현재 phase와 ticket 상태
- [Outcome Roadmap And WBS](docs/WBS.md): 순서, dependency와 evidence gate
- [Tickets](docs/tickets/), [Decisions](docs/decisions/), [Open Questions](docs/OPEN_QUESTIONS.md): 상세 범위, 결정과 미결 선택

## 핵심 경계

- 앱 소유 DB와 Blob이 정본이며 Obsidian, 운영체제 Calendar, Discord와 MCP는 필수 runtime dependency가 아닙니다.
- Conversation, Knowledge, Calendar와 Embedding은 별도 저장 경계를 유지하고, Embedding은 재생성 가능한 파생 저장소입니다.
- 모델 출력이나 request body의 owner ID를 권한 근거로 사용하지 않습니다.
- 핵심 local flow는 인터넷 없이 동작하고 외부 ingress는 검증된 Cloudflare Tunnel 경계 뒤에서만 허용합니다.
- 실제 개인 데이터, credential, DB, Blob, model weight와 로컬 설정은 저장소에 커밋하지 않습니다.

## Security

2026-07-27 sanitized current tree를 새 public repository history에 반입해 저장소를 다시 시작했습니다. 재시작 시점의 reachable history는 세 commit뿐이며 과거 `vendor/password-blocklist/`, updater와 embedded blocklist module 경로가 없고 unreachable Git object나 추적 파일의 원본 corpus도 발견되지 않았습니다. [POV-031](docs/deps/POV-031-remove-password-blocklist-feature.md)의 immutable migration과 sentinel/legacy compatibility는 그대로 보존합니다. 기존 history 정리 계획인 [POV-032](docs/deps/POV-032-purge-password-blocklist-history-and-caches.md)는 현재 저장소에 적용할 작업이 없어 superseded archive로 닫았습니다.

이 검증은 현재 저장소의 reachable object와 추적 파일 경계만 설명합니다. 이전 저장소에서 제3자가 만들었을 수 있는 clone, cache, screenshot 또는 offline archive가 없음을 보증하지 않습니다.

## License

별도 표기가 없는 이 저장소의 프로젝트 소스 코드는 [MIT License](LICENSE)에 따라 배포됩니다. 외부 dependency는 각 dependency의 고유 라이선스를 따릅니다.
