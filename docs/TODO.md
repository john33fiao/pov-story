# TODO

Last updated: 2026-07-31

Current phase: H6 follow-on direction accepted; H0 completed including Windows workspace validation baseline; H1 single-owner product delivery active; external POV-022 research deferred until the personal product is complete or explicitly reprioritized

Repository posture: public fresh-history baseline verified 2026-07-27; POV-031 compatibility preserved, POV-032 superseded by repository restart, project-owned code licensed under MIT

## Security Remediation

| Item | Status | Outcome |
| --- | --- | --- |
| Fresh public repository baseline | Completed — 2026-07-27; new three-commit reachable history and tracked-content hygiene verified | sanitized current tree만 반입했고 과거 corpus/updater/module path와 unreachable object가 없음; 이전 저장소의 외부 copy 부재까지 보증하지 않음 |
| [POV-034 Restore Windows workspace validation baseline](deps/POV-034-restore-windows-workspace-validation-baseline.md) | Completed — Windows workspace와 Unix auth suite verified 2026-07-27 | Unix auth maintenance 경계를 유지하면서 Windows `pov-core`/workspace compile·test baseline 복구 |
| [POV-031 Remove password blocklist feature](deps/POV-031-remove-password-blocklist-feature.md) | Completed — 2026-07-27; ADR-0005 Accepted, current-tree removal and compatibility verified | corpus, updater와 enforcement를 제거하고 sentinel/legacy persisted compatibility를 fail closed로 보존 |
| [POV-032 Purge password blocklist history and caches](deps/POV-032-purge-password-blocklist-history-and-caches.md) | Superseded — 2026-07-27 repository restart | 기존 history-remediation 절차는 새 저장소에 적용할 대상이 없어 archive로 닫고 현재 저장소 검증 경계만 보존 |

## Now

H1 always-on backend와 dogfood runtime은
[ADR-0006](decisions/0006-h1-development-and-dogfood-platform.md)에서 MacBook의 macOS로
결정했습니다. Windows는 구현과 cross-platform validation에 사용하며 native Windows
production auth는 POV-010의 선행 조건이 아닙니다.

| Item | Type | Status | Outcome |
| --- | --- | --- | --- |
| [ADR-0006 H1 development and dogfood platform](decisions/0006-h1-development-and-dogfood-platform.md) | Decision gate | Accepted — 2026-07-31 | macOS를 always-on/dogfood backend로, Windows를 development/cross-platform validation으로 고정 |
| [POV-010 Minimal authenticated local text chat](tickets/POV-010-minimal-authenticated-local-text-chat.md) | Delivery | Completed — 2026-07-31; core/API/Web 및 pinned frontend/Rust baseline PASS | owner-scoped login/refresh/logout, text capture, durable receipt와 stored timeline을 Windows/WSL의 component·contract·repository evidence로 검증 |
| [POV-011 Authenticated replayable job status stream](deps/POV-011-authenticated-replayable-job-status-stream.md) | Delivery | Completed — 2026-07-31; Core/API/Web/Chromium 및 actual macOS locked baseline PASS | token refresh와 reconnect 뒤에도 owner-scoped durable status cursor를 이어 보는 흐름; Linux runtime 사용은 제공하지 않으며 completion gate가 아님 |

## Auth Follow-ups — Not Initial H1 Gates

| Ticket | Type | Status | Activation boundary |
| --- | --- | --- | --- |
| [POV-035 Planned key rotation and retirement operator](tickets/POV-035-planned-key-rotation-and-retirement-operator.md) | Delivery | Planned — maintenance core implemented, production operator absent | 장기 key maintenance와 release claim 전 |
| [POV-036 Auth key compromise and loss recovery](tickets/POV-036-auth-key-compromise-and-loss-recovery.md) | Delivery | Planned — ADR contract accepted, persisted transition/operator 미구현 | compromise/loss recovery 지원 claim 전 |
| [POV-037 Auth platform and durability hardening](tickets/POV-037-auth-platform-and-durability-hardening.md) | Hardening evidence | Planned — explicit evidence backlog | 해당 platform, reference-device performance 또는 durability claim 전 |
| [POV-038 macOS dogfood runtime and installed-browser evidence](tickets/POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md) | Platform activation evidence | Backlog — target MacBook unavailable | MacBook을 확보한 뒤 macOS always-on/dogfood production 및 installed-browser 지원을 주장하기 전 |

POV-010은 자동화된 component·HTTP contract와 supported-Unix smoke로 구현 delivery를
완료했습니다. MacBook production `auth init`, listener와 installed-browser
login/refresh/logout·cookie/storage evidence는 장비 확보 뒤 POV-038에서 실행합니다.
Native Windows auth maintenance/runtime은 현재 성공으로 주장하지 않으며, 중간
개발·cross-platform validation에만 사용합니다.

## Next

| Horizon | Status | Outcome | Tickets |
| --- | --- | --- | --- |
| H0 — Reproducible local boundary | Completed including Windows validation repair | same-origin shell, source/store/auth와 process safety contract를 executable evidence로 재현 | [POV-001](deps/POV-001-local-offline-walking-skeleton.md), [POV-004](deps/POV-004-core-data-identity-and-store-boundaries.md), [POV-005](deps/POV-005-authentication-and-session-security-decision.md), [POV-006](deps/POV-006-provider-ports-and-safe-process-supervisor.md), [POV-034](deps/POV-034-restore-windows-workspace-validation-baseline.md) |
| H1 — Trustworthy text capture | In Progress — POV-007/008/009/010/011 completed; continues with POV-012 | 한 owner가 offline에서 text를 durable하게 남기고 retry·status·local inference failure를 신뢰 | [POV-007](deps/POV-007-local-login-refresh-and-session-revoke.md), [POV-008](deps/POV-008-idempotent-conversation-append-and-outbox.md), [POV-009](deps/POV-009-durable-single-slot-job-queue.md), [POV-010](tickets/POV-010-minimal-authenticated-local-text-chat.md), [POV-011](deps/POV-011-authenticated-replayable-job-status-stream.md), [POV-012](tickets/POV-012-loopback-llm-text-round-trip.md), [POV-013](tickets/POV-013-conversation-core-offline-evidence-gate.md) |
| H2 — Correctable voice recall | Gated by POV-013 | 음성을 교정 가능한 current revision으로 만들고 근거와 함께 recall하며 raw audio를 policy대로 purge | [POV-002 epic](tickets/POV-002-voice-lifelog-round-trip.md), [POV-014](tickets/POV-014-temporary-blob-lifecycle-and-privacy-contract.md), [POV-015](tickets/POV-015-authenticated-idempotent-voice-intake.md), [POV-033](tickets/POV-033-windows-python-whisper-turbo-provider.md), [POV-016](tickets/POV-016-supervised-audio-normalization-and-transcription.md), [POV-017](tickets/POV-017-immutable-transcript-correction-revisions.md), [POV-018](tickets/POV-018-current-revision-hybrid-transcript-retrieval.md), [POV-019](tickets/POV-019-retry-safe-audio-purge.md), [POV-020](tickets/POV-020-evidence-grounded-next-day-recall.md), [POV-023](tickets/POV-023-source-derivative-reconciliation.md), [POV-021](tickets/POV-021-voice-round-trip-evidence-gate.md) |

실행 순서, dependency와 horizon exit evidence는 [Outcome Roadmap And WBS](WBS.md)를 따릅니다.

## Later — Ticket After Evidence

- H3: Trusted daily knowledge — document revision, daily note/task, activity log와 approved memory
- H4: Internal time continuity — external Calendar 없는 event CRUD, revision, timezone과 notification
- H5: Safe product access and recovery — full PWA, explicit export/delete, backup/restore와 선택적 Cloudflare ingress
- Product validation: [POV-022](tickets/POV-022-first-segment-and-voice-wedge-discovery-gate.md) — 개인용 H1~H5 완성 뒤 first segment, voice wedge, correction/source trust와 purge expectation을 외부 사용자에게 검증
- H6: Persistent playable story continuity — 독자가 선택·관계·세계 상태·엔딩을 회차 사이에 이어 가는 후속 제품 방향

H3~H5 상세 delivery ticket은 [POV-021](tickets/POV-021-voice-round-trip-evidence-gate.md)의 product evidence를 검토한 뒤 만듭니다. H6는 장기 방향을 보존하기 위한 discovery·prototype·decision backlog만 작성합니다. H5 outcome evidence와 명시적 priority 뒤에 POV-025를 활성화하고, production ticket은 POV-029가 진입을 accepted하기 전에는 만들지 않습니다. multiple workers, PostgreSQL/vector adapter와 optional tools는 측정된 trigger가 생길 때만 roadmap commitment로 올립니다.

## Strategic Backlog — H6

| Ticket | Type | Status | Outcome |
| --- | --- | --- | --- |
| [POV-024 Storyworld follow-on outcome](tickets/POV-024-storyworld-follow-on-outcome.md) | Epic | Planned | reader-first H6 outcome과 evidence sequence 소유 |
| [POV-025 Reader demand and positioning](tickets/POV-025-storyworld-reader-demand-and-positioning.md) | Discovery gate | Gated by H5 evidence/priority | first reader, initial genre와 회차형 playable-story demand 결정 |
| [POV-026 Serialized story loop prototype](tickets/POV-026-serialized-story-loop-prototype.md) | Prototype gate | Gated by POV-025 | scene, choice, branch와 다음 회차 resume의 playability 검증 |
| [POV-027 Persistent world state experience gate](tickets/POV-027-persistent-world-state-experience-gate.md) | Experience gate | Gated by POV-026 | 관계·세계 상태·발견·ending condition의 continuity와 recovery 검증 |
| [POV-028 Creator authoring and monetization validation](tickets/POV-028-creator-authoring-and-monetization-validation.md) | Discovery gate | Gated by POV-025/027 | playable world 제작 workflow, publishing 및 monetization 가설 검증 |
| [POV-029 Storyworld architecture and safety decision](tickets/POV-029-storyworld-architecture-and-safety-decision.md) | Decision gate | Gated by each POV-025~028 `proceed`/`narrow` | account/data/runtime/safety/rights/cost/commerce 경계와 production 투자 결정 |

## Decision Gates

- [x] [POV-034](deps/POV-034-restore-windows-workspace-validation-baseline.md)에서 POV-031 선행 Windows workspace compile/test baseline 복구
- [x] [ADR-0005](decisions/0005-password-blocklist-removal-and-legacy-auth-compatibility.md)에서 POV-031 persisted compatibility 전략 승인 및 [POV-031](deps/POV-031-remove-password-blocklist-feature.md) current-tree 제거 완료
- [x] 완료된 POV-031 current-tree inventory를 근거로 project-owned code에 MIT License 적용
- [x] 새 public repository history와 tracked-content baseline을 확인하고 POV-032를 superseded archive로 종료
- [ ] 외부 contribution을 받을 경우 제출·검토·라이선스 동의 정책 결정
- [ ] 개인용 H1~H5 완성 또는 명시적 재우선순위 결정 뒤 POV-022 외부 사용자 검증 활성화
- [x] POV-001에서 Rust toolchain, Node version, package manager를 실제 manifest와 함께 고정
- [x] [ADR-0004](decisions/0004-local-authentication-and-session-security-contract.md)에서 authentication cryptography, key lifecycle과 refresh lifetime 결정
- [x] [ADR-0006](decisions/0006-h1-development-and-dogfood-platform.md)에서 MacBook
  macOS를 H1 always-on/dogfood backend로, Windows를 development/cross-platform validation
  환경으로 결정
- [ ] Target MacBook 확보 뒤 [POV-038](tickets/POV-038-macos-dogfood-runtime-and-installed-browser-evidence.md)에서
  macOS production auth와 installed-browser dogfood evidence 실행
- [ ] POV-014에서 temporary Blob encryption, retention, quota와 irreversible purge contract 결정
- [ ] model/runtime artifact pinning과 versioned quality gate 결정
- [ ] backup, export, restore와 explicit purge policy 결정
- [ ] public product naming과 `POV Story` working title 충돌 해결
- [ ] POV-025에서 H6 first reader, initial genre와 serialized playable-story demand 검증
- [ ] POV-027에서 관계·세계 상태·ending continuity와 recovery 경험 검증
- [ ] POV-029에서 storyworld account/data/runtime/safety/rights/cost/commerce 경계 결정
- [ ] personal lifelog의 storyworld 사용 전 default-off opt-in, 격리, 철회, 삭제와 retention 결정

전체 미결정 목록은 [Open Questions](OPEN_QUESTIONS.md)에 유지합니다. 후보를 확정값처럼 구현하지 않습니다.

## Initialization Verification

- [x] 2026-07-27 새 public repository visibility와 fresh reachable-history baseline 확인
- [x] README, architecture, TODO, WBS, tickets, decisions, refs/deps spine 작성
- [x] `.agents`, `.codex`, `AGENTS.md`를 local-only ignore 대상으로 분리
- [x] public data/secret ignore policy 작성
- [x] POV-031 current-tree inventory 뒤 project-owned code에 MIT License 적용
- [ ] 외부 contribution policy 별도 결정

## Recently Completed

- 2026-07-31: [POV-010](tickets/POV-010-minimal-authenticated-local-text-chat.md) owner-scoped conversation API와 login/refresh/logout text composer, authoritative durable readback, Node `26.4.0`/npm `11.17.0` frontend 및 Rust repository baseline delivery 완료.
- 2026-07-29: [POV-009](deps/POV-009-durable-single-slot-job-queue.md) outbox-backed enqueue, fixed-normal FIFO, fenced single-slot lease, conservative recovery halt와 durable retry/cancellation/timing/event persistence delivery 완료.
- 2026-07-29: [POV-008](deps/POV-008-idempotent-conversation-append-and-outbox.md) owner-scoped idempotent append, transactional outbox/audit, post-commit readback와 cross-owner fail-closed persistence delivery 완료.
- 2026-07-29: [POV-007](deps/POV-007-local-login-refresh-and-session-revoke.md) narrowed local auth runtime의 supported-Unix production `auth init`, listener-ready/second-init no-replace smoke와 final repository validation 완료.
- 2026-07-27: 새 public repository의 fresh reachable history와 tracked-content hygiene를 확인하고 [POV-032](deps/POV-032-purge-password-blocklist-history-and-caches.md)를 repository restart로 superseded 처리.
- 2026-07-27: [POV-031](deps/POV-031-remove-password-blocklist-feature.md) ADR-0005 Accepted, current-tree corpus/updater/enforcement 제거와 sentinel/legacy persisted compatibility 검증 완료.
- 2026-07-27: [POV-034](deps/POV-034-restore-windows-workspace-validation-baseline.md) Unix-only auth record module/import/type gate alignment, Windows workspace check/test and Unix auth maintenance regression evidence completed.
- 2026-07-25: [POV-006](deps/POV-006-provider-ports-and-safe-process-supervisor.md) provider ports, actual-byte provenance and macOS/POSIX one-shot process trust, bounded output, cancellation/tree cleanup evidence completed.
- 2026-07-25: [POV-005](deps/POV-005-authentication-and-session-security-decision.md) authentication/session security contract, ADR-0004 and synthetic loopback cookie negative evidence completed.
- 2026-07-25: [POV-004](deps/POV-004-core-data-identity-and-store-boundaries.md) typed identity/revision contracts, four isolated SQLite lifecycle boundaries and synthetic negative evidence completed.
- 2026-07-25: [POV-001](deps/POV-001-local-offline-walking-skeleton.md) local-only Rust/Axum and React/Vite same-origin walking skeleton, validation and browser evidence completed.
- 2026-07-25: [POV-030](deps/POV-030-storyworld-follow-on-backlog.md) storyworld follow-on direction, ADR-0003 and H6 evidence-gated backlog completed.
- 2026-07-25: [POV-003](deps/POV-003-product-direction-and-outcome-roadmap.md) product direction, outcome roadmap and first product-gate backlog completed.
- 2026-07-24: repository initialization documents and collaboration gates prepared.
