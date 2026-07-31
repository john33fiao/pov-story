# Open Questions

이 문서는 아직 결정되지 않은 항목만 관리합니다. 후보값을 accepted architecture로 해석하지 않습니다. 결정이 내려지면 ADR을 만들고 이 목록에서 제거하거나 상태를 갱신합니다.

## Storage And Retrieval

- SQLite에서 PostgreSQL로 이동할 data volume, concurrent user, operational complexity 기준은 무엇인가?
- exact cosine에서 SQLite vector adapter 또는 PostgreSQL pgvector로 이동할 data size/P95 기준은 무엇인가?
- KURE GGUF와 SentenceTransformers 기준 사이 허용할 cosine/ranking 편차는 얼마인가?
- Knowledge immutable snapshot revision을 압축·정리하기 시작할 기준은 무엇인가?
- 모든 일반 conversation을 검색할지, 명시적 기록만 Knowledge로 승격할지?
- provisional transcript를 검색에 노출할 범위는 어디까지인가?

## Audio, Model, And Runtime

- temporary Blob 암호화 방식과 기본 7일 retention의 사용자 설정 범위는?
- Gemma, KURE와 platform별 Whisper runtime/model의 최종 artifact revision/hash와 quality
  gate는?
- Windows Python OpenAI Whisper와 다른 platform의 whisper.cpp 사이 backend 선택,
  중요한 음성용 profile과 자동/수동 전환 조건은?
- CUDA unavailable에서 Python Whisper를 unavailable로 닫을지, 별도 측정된 CPU profile을
  허용할지?
- llama.cpp, Python/Whisper distribution, whisper.cpp와 FFmpeg binary의
  pin/update cadence/rollback policy는?

## Identity And Security

- Discord identity와 Web account를 연결·복구하는 방식은?
- multi-user 전환 시 queue fairness, per-user quota, TOTP/WebAuthn과 external recovery policy는?

## Product Scope

- `POV Story` working title과 lifelogging product의 공개 이름은 언제 어떤 검증 뒤에 확정할 것인가?
- Calendar recurrence, multi-day event, notification의 MVP 범위는?
- daily/weekly summary 실행 시각과 regeneration policy는?
- web search/image tool의 cost, approval, retention policy는?

## H6 Storyworld

- 첫 reader segment와 initial genre는 무엇이며 어떤 행동 evidence가 serialized playable-story demand를 통과시키는가?
- 회차, 선택, 관계, 세계 상태와 ending continuity 중 반복 사용에 필수인 최소 조합은 무엇인가?
- storyworld는 lifelogging과 account/control plane/source store를 공유할지 별도 bounded context로 격리할지?
- 개인 lifelog를 story context로 사용할 가치가 있는지, 있다면 default-off opt-in, 목적 제한, 철회, export, deletion과 retention을 어떻게 보장할지?
- local, cloud 또는 hybrid inference 중 어떤 profile이 quality, latency, cost, privacy와 concurrency gate를 충족하는가?
- reader/creator content의 age suitability, moderation, copyright, attribution, takedown과 appeal 책임은 어디에 있는가?
- creator world와 generated episode의 ownership, versioning, publishing, refund와 settlement 범위는 무엇인가?
- reader value와 creator 제작 가능성이 검증된 뒤 어떤 monetization 후보를 어떤 unit-economics gate로 비교할 것인가?

## Operations And Public Project

- MacBook macOS H1 runtime의 exact OS/browser version, service launch 방식과 backup/restore
  evidence를 어떤 release gate에서 고정할 것인가?
- Cloudflare zone, Tunnel replica, WAF/rate limit/Turnstile baseline과 incident alert는?
- backup, export, restore, explicit purge policy와 recovery objective는?
- 외부 contribution을 받을 경우 제출, 검토와 라이선스 동의 정책을 어떻게 정의할 것인가?
