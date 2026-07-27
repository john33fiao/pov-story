# ADR-0001: Local-first Modular Monolith Baseline

- Status: Accepted
- Date: 2026-07-24

## Context

POV Story는 개인의 대화, 음성, 일정, 지식, 장기 기억을 다루며 인터넷과 외부 사용자 앱이 없어도 핵심 기능이 동작해야 합니다. 초기 구현은 한 장치에서 작게 시작하되 source data, derived index, local inference, 향후 multi-user 및 PostgreSQL 확장을 혼동하지 않아야 합니다.

## Decision

- Rust stable, Axum, Tokio 기반 modular monolith control plane을 사용합니다.
- React, TypeScript, Vite static SPA를 Rust가 API와 same-origin으로 제공합니다.
- Conversation, Knowledge, Calendar, Embedding을 별도 SQLite WAL DB로 시작합니다.
- Blob은 DB 밖의 app-managed content-addressed store로 관리합니다.
- source DB transaction과 outbox를 사용하고 Embedding을 재생성 가능한 derivative로 둡니다.
- DB access는 domain repository 뒤에 두고 PostgreSQL adapter/migration을 별도 경계로 설계합니다.
- local inference server는 loopback-only long-running process로 감독합니다.
- media CLI는 shell 없이 per-job child process로 실행합니다.
- MVP 실행 slot은 하나이며 같은 priority 안에서 FIFO입니다.
- local Web Chat은 `127.0.0.1:8080`에서 offline으로 동작해야 합니다.
- 외부 ingress는 Cloudflare Tunnel 뒤에서만 제공합니다.

Gemma 4 E2B, KURE-v1, Whisper multilingual base와 구체 quantization은 이 ADR의 영구 결정이 아니라 benchmark 후보입니다.

## Consequences

장점:

- 외부 앱과 network 장애가 source data 접근을 막지 않습니다.
- DB별 failure/backup/migration 경계가 명확합니다.
- generated embedding index를 버리고 다시 만들 수 있습니다.
- model/backend 교체가 domain data model을 바꾸지 않습니다.
- 한 process deployment로 MVP 운영을 단순화할 수 있습니다.

비용:

- 네 DB의 migration, backup, reconciliation을 각각 관리해야 합니다.
- cross-domain consistency는 distributed transaction이 아니라 outbox/idempotency로 해결해야 합니다.
- Rust와 frontend build toolchain을 함께 관리해야 합니다.
- local model benchmark와 process supervision이 release gate가 됩니다.

## Revisit When

- 외부 app sync가 product requirement가 됨
- raw audio 영구 보존이 필요함
- cloud inference가 mandatory path가 됨
- single execution slot이 measured workload를 충족하지 못함
- SQLite 또는 exact cosine이 agreed scale/latency gate를 넘음
- shared multi-user workspace가 MVP scope가 됨
