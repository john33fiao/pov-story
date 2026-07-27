# POV-022 First Segment And Voice Wedge Discovery Gate

Status: In Progress

Research plan: v1 registered 2026-07-25

Type: Discovery gate

Roadmap: H-1 — Problem and wedge evidence

## Why

first segment, 하나의 chat capture, voice recall, correction/source 표시와 기본 7일 raw-audio purge는 아직 사용자 evidence가 없는 핵심 제품 가설입니다. H1 구현에 들어가기 전에 낮은 비용으로 문제와 wedge가 맞는지 확인해야 합니다.

## What

problem interview, low-fidelity chat walkthrough와 concierge-style capture/next-day recall test를 수행합니다. participant profile, sample, evidence threshold와 stop rule을 실행 전에 고정하고 결과를 `proceed`, `narrow`, `pivot` 또는 `stop`으로 결정합니다.

## Delivery Units

1. [x] participant profile, sample, task, evidence taxonomy, threshold, stop rule와 public-repository safety를 research 전에 사전 등록
2. [ ] 외부 participant 모집, consent, problem interview, walkthrough와 24~48시간 뒤 concierge recall 실행
3. [ ] anonymized evidence aggregation, `proceed`/`narrow`/`pivot`/`stop` 결정과 Product Strategy/WBS readback

첫 단위만 저장소에서 독립적으로 완료할 수 있습니다. 두 번째 단위는 실제 participant와 별도 access-controlled research storage가 필요하며, 아래 결과를 충족했다고 추정하거나 synthetic response로 대체하지 않습니다.

## Scope

- first-segment problem and current-alternative interview
- text versus voice capture walkthrough
- transcription correction and source/revision trust concept test
- next-day recall concierge test
- raw audio 7-day expiry, playback/export and purge expectation test
- local setup/privacy value versus friction discussion
- anonymized evidence summary and strategy decision

## Out Of Scope

- production application code
- actual private audio or lifelog fixture commit
- statistically representative market sizing
- storyworld product validation; H6 전용 [POV-025](POV-025-storyworld-reader-demand-and-positioning.md)가 소유
- model quality benchmark
- pricing or monetization

## Pre-registered Research Plan v1

### Freeze And Change Control

- 이 문서의 hypothesis, profile, sample, task copy/rotation, denominator, threshold, exclusion과 decision rule은 participant outreach 전에 등록한 core plan v1입니다.
- 첫 outreach 전에 recruitment channel과 source pool, invitation copy, facilitator, compensation, contact order, quota handling, referral, screener/scheduling/session tool, standard reminder와 processor/data flow를 `POV-022-v1` execution manifest로 고정하고 사용자 승인을 받습니다. manifest가 없으면 연락이나 screening을 시작하지 않습니다.
- 첫 outreach 뒤 manifest를 바꾸거나 첫 eligible participant의 Session 1 뒤 core plan을 바꿔야 하면 current round를 `INVALID`로 닫고 변경 이유를 기록한 새 version을 먼저 review합니다. 서로 다른 version의 evidence를 한 denominator로 합치지 않습니다.
- contacted, screened-out, declined, eligible, enrolled, no-show, withdrawn, excluded와 completed disposition은 private recruitment log에 빠짐없이 기록하되 public repository에는 aggregate count만 남깁니다.
- 실제 participant response, private content 또는 기대 결과를 이 계획에 미리 채우지 않습니다.

### Decision To Inform

POV-022는 다음 질문 하나를 결정합니다.

> 최근 개인 기록을 여러 surface에 남기고 다시 찾는 1인 사용자가 local-first source/revision trust를 가치 있게 여기며, voice capture를 첫 wedge로 사용할 행동 evidence가 충분해 H1 delivery를 시작할 수 있는가?

`proceed` 또는 accepted `narrow` 전에는 POV-007 이후 H1 ticket을 Ready로 올리지 않습니다. `narrow`, `pivot` 또는 `stop`이 first segment, value proposition 또는 roadmap을 바꾸면 구현보다 Product Strategy, WBS, TODO와 필요 ADR readback을 먼저 수행합니다.

### Primary XYZ Hypothesis

> 첫 6명의 qualified participant 중 최소 4명은 text와 voice capture를 모두 수행한 뒤 자유 선택 capture에서 voice를 선택하고, 24~48시간 안의 pre-booked delayed session에서 corrected current source/revision을 사용한 recall task를 완료한다.

compliment, future intent 또는 “쓸 것 같다”는 이 가설의 성공으로 세지 않습니다. controlled task completion, method choice와 pre-booked delayed-task completion만 primary evidence입니다.

### Participant Profile And Fixed Sample

모든 participant는 다음 조건을 충족합니다.

- 만 18세 이상이며 자신의 개인 기록을 혼자 관리합니다.
- 최근 30일 안에 개인 note, reminder, voice memo 또는 유사한 기록을 세 번 이상 남겼고 두 개 이상의 app, file 또는 surface를 사용했습니다.
- 최근 30일 안에 하루 이상 지난 개인 기록을 다시 찾으려 한 구체적 사례가 있습니다. 민감한 실제 내용 자체는 묻거나 수집하지 않습니다.
- 한국어 text와 짧은 한국어 voice task를 수행할 수 있습니다.
- 이 저장소의 contributor, 계획 작성자 또는 기대 결과를 미리 전달받은 사람은 정규 sample에서 제외합니다. owner dogfood는 별도 참고 evidence이며 threshold denominator에 넣지 않습니다.

표본은 `n=6`으로 고정하고 두 behavior stratum을 각각 세 명씩 채웁니다.

- `STR-VOICE`: 최근 30일에 voice memo 또는 dictation을 두 번 이상 사용한 세 명
- `STR-TEXT`: 최근 30일에 voice 사용이 0~1회이고 text capture가 주된 세 명

각 stratum에서 eligibility와 consent를 충족하고 Session 1을 시작한 순서대로 아래의 frozen slot list에서 다음 ID를 부여합니다.

- `STR-VOICE`: `P01` → `P04` → `P06`
- `STR-TEXT`: `P02` → `P03` → `P05`

facilitator는 participant 특성, scheduling 또는 앞선 결과를 보고 slot을 고르거나 건너뛰거나 교환하지 않습니다. Session 1 뒤 Session 2에 오지 않으면 recall/return 실패로 세며 편의를 위해 교체하지 않습니다. participant가 consent를 철회해 evidence 삭제를 요청하거나 substantive task evidence가 생기기 전 연구 측 technical failure가 발생한 경우에만 같은 stratum의 다음 eligible participant가 비워진 ID와 assignment를 그대로 승계하며 exclusion reason을 aggregate record에 남깁니다.

`n=3`인 각 stratum 안에서는 odd/even assignment가 각각 `1:2` 또는 `2:1`로 불균형합니다. 대신 전체 sample은 odd/even 세 명씩으로 균형을 유지하며, 이 작은 표본에서 stratum별 effect나 assignment effect를 분리해 주장하지 않습니다.

이 작은 purposive sample은 시장 대표성이나 prevalence를 추정하지 않습니다. 첫 segment와 wedge를 다음 delivery에 투자할 정도로 좁힐 directional gate입니다.

### Method And Task Order

#### Screening And Consent

- participant 연락 또는 screening 전에 recruitment, screener, scheduling, Session 1/2, voice transport, notes와 consent에 쓰는 exact tool·account·processor를 participant-facing data-flow sheet에 고정합니다. 각 tool의 recording, auto-transcription, AI note, telemetry, cloud transfer, storage, backup과 deletion behavior를 적고 승인되지 않은 기능은 끕니다.
- screener는 위 past behavior와 stratum만 확인하고 product pitch, solution preference 또는 민감한 기록 내용을 묻지 않습니다.
- Session 2는 enrollment 때 24~48시간 window 안으로 미리 예약합니다.
- 모든 participant에게 Session 2 두 시간 전에 같은 channel로 정답, stored content 또는 product claim이 없는 standard reminder를 정확히 한 번 보냅니다. 추가 chase는 하지 않습니다.
- facilitator는 목적, voluntary participation, 중단·철회 방법, 수집 field, exact data flow, processor, 보관·삭제 시점과 녹음 여부를 설명하고 명시적 consent 뒤에만 시작합니다.

#### Participant-facing Consent Checklist

실제 consent artifact는 execution manifest의 exact tool/data flow와 함께 participant에게 제공하고 다음을 모두 포함합니다.

- 목적은 POV-022 first-segment/voice-wedge decision 한 번으로 제한하며 다른 product research, marketing, model training 또는 model-quality evaluation에 raw data를 재사용하지 않습니다.
- screener, contact, consent, live voice, task choice, facilitator note와 delayed-task field 중 무엇을 수집하는지 구분합니다.
- exact tool, account, processor/recipient, live audio 전송, telemetry, recording/auto-transcription/AI note 상태와 storage location을 알립니다.
- recording은 기본 off이고 별도 opt-in입니다. recording 거부가 참여나 compensation을 불리하게 만들지 않습니다.
- public repository에는 aggregate count, 3명 이상 non-linkable grouped theme와 decision만 들어가며 participant/evidence ID, direct quote와 participant-level paraphrase는 공개하지 않습니다.
- withdrawal code 사용 방법, decision publication 전 cutoff, 삭제할 data와 publication 뒤 7일 안에 code mapping을 삭제해 이후 individual contribution을 찾을 수 없다는 한계를 설명합니다.
- compensation이 있으면 답변 내용, task PASS, 완료 또는 withdrawal 여부와 무관한 지급 기준을 사전에 고정하고, 이미 발생한 compensation을 부정적 답변이나 withdrawal 때문에 회수하지 않습니다.
- data type별 primary/trash/version deadline, recording/contact backup 포함 최대 37일, consent/raw-note backup 포함 최대 120일의 true maximum과 deletion confirmation 방법을 알립니다.

#### Task Artifact And Assignment v1

아래 copy, assignment, condition, position과 scoring key가 v1 artifact입니다. spelling, field 수, seeded error 또는 task order를 facilitator가 현장에서 바꾸지 않습니다.

interaction surface는 production app이 아닌 facilitator-controlled static chat board입니다. board 자체는 network, analytics, persistence, microphone capture 또는 model call을 사용하지 않습니다.

- text path: participant가 exact card를 한 multiline field에 입력하고 `텍스트로 기록`을 선택합니다.
- voice path: participant가 `말하기 시작`을 선택하고 card를 소리 내어 읽은 뒤 `말하기 끝`을 선택합니다. facilitator는 실제 ASR 대신 아래 frozen transcript fixture를 board에 표시합니다.
- free-choice screen: 홀수 participant는 `말로 기록`을 왼쪽, 짝수 participant는 `텍스트로 기록`을 왼쪽에 둡니다. button 크기와 설명은 동일합니다.
- Session 2 board는 v1에 정의한 synthetic stored items만 다시 표시합니다. 실제 저장, login, model quality 또는 notification behavior를 흉내 내거나 성공 evidence로 세지 않습니다.

board delivery tool과 live voice transport는 execution manifest에서 exact artifact/version과 processor를 고정합니다. board copy나 interaction을 바꾸면 같은 v1 evidence로 합치지 않습니다.

| Card | Exact synthetic copy | Purpose |
| --- | --- | --- |
| `CARD-A` | `가상 프로젝트 라임 / 표지: 파랑 / 검토: 화요일 16:00` | controlled capture |
| `CARD-B` | `가상 프로젝트 코발트 / 표지: 초록 / 검토: 목요일 11:00` | controlled capture |
| `CARD-C` | `가상 프로젝트 앰버 / 표지: 노랑 / 검토: 금요일 14:00` | post-exposure free-choice capture |
| `CASE-D-v1` | `가상 프로젝트 델타 / 검토: 월요일 10:00` | stale matched case |
| `CASE-D-v2` | `가상 프로젝트 델타 / 검토: 월요일 13:00` | corrected matched case |
| `CASE-E-v1` | `가상 프로젝트 에코 / 검토: 수요일 09:00` | stale matched case |
| `CASE-E-v2` | `가상 프로젝트 에코 / 검토: 수요일 12:00` | corrected matched case |

voice에 배정된 capture card의 v1 transcript만 하나의 error를 가집니다. `CARD-A`가 voice면 `파랑`을 `빨강`으로, `CARD-B`가 voice면 `초록`을 `보라`로 바꾸며 다른 field는 정확히 유지합니다. 이는 actual STT quality가 아니라 controlled correction interaction을 검증하는 fixture입니다.

`CASE-D`와 `CASE-E`는 서로 반복 노출하지 않는 matched cases입니다. `labeled` case는 v1에 `source: original capture / revision: stale`, v2에 `source: user correction / revision: current`를 표시하고, `hidden` case는 두 metadata를 모두 숨깁니다. facilitator는 “후속 행동에 사용할 검토 시각을 선택해 주세요”라고만 말합니다.

| Participant | Capture assignment | First comparison | Second comparison |
| --- | --- | --- | --- |
| `P01` | `CARD-A voice`, `CARD-B text` | `CASE-D labeled`, current left | `CASE-E hidden`, current right |
| `P02` | `CARD-A text`, `CARD-B voice` | `CASE-D hidden`, current right | `CASE-E labeled`, current left |
| `P03` | `CARD-A voice`, `CARD-B text` | `CASE-E hidden`, current left | `CASE-D labeled`, current right |
| `P04` | `CARD-A text`, `CARD-B voice` | `CASE-E labeled`, current right | `CASE-D hidden`, current left |
| `P05` | `CARD-A voice`, `CARD-B text` | `CASE-D labeled`, current left | `CASE-E hidden`, current right |
| `P06` | `CARD-A text`, `CARD-B voice` | `CASE-D hidden`, current left | `CASE-E labeled`, current right |

capture completion은 project label, 표지 색과 검토 시각 세 field가 해당 method에 남아야 PASS입니다. correction은 seeded color를 원래 card 값으로 되돌려야 PASS입니다. metadata choice는 labeled/hidden case 각각에서 v2 time을 고르면 participant-level current-choice PASS로 기록합니다.

#### Session 1 — 35~45 Minutes

1. 15~20분 problem interview로 최근 실제 capture와 later-recall behavior, current alternative, 실패와 workaround를 solution construct를 먼저 말하지 않는 중립 질문으로 확인합니다.
2. participant는 assignment table에 따라 `CARD-A`와 `CARD-B` 하나를 text로, 하나를 voice로 capture합니다.
3. 두 방법을 모두 수행한 직후 `CARD-C`를 원하는 방법으로 capture하게 합니다. facilitator는 voice 또는 text를 권하지 않습니다.
4. free-choice가 끝난 뒤 assigned voice transcript v1의 exact seeded error를 제시합니다. participant가 발견·교정하는지, 도움을 얼마나 요청하는지 관찰합니다.
5. assignment table의 labeled case와 hidden case를 정해진 order/position으로 한 번씩 보여 줍니다. 어느 time을 근거로 행동하는지 기록하며 같은 case를 metadata 전후로 반복 노출하지 않습니다.
6. transcript는 보존되지만 raw audio가 기본 7일 뒤 삭제되는 구체 정책과 `지금 삭제`, `7일 뒤 삭제`, `명시적 export 후 삭제`, `장기 raw 보존 필요` 선택지를 보여 줍니다. 이는 observed retention behavior가 아니라 policy preference evidence로 별도 분류합니다.

synthetic card는 실제 사람, 회사, 일정, 위치 또는 participant의 private fact를 포함하지 않습니다. 각 card는 서로 다른 가상 project label, 색상, 요일과 시각처럼 recall 여부를 판정할 수 있는 비민감 field만 사용합니다. card 내용이 synthetic이어도 participant의 live voice는 personal data일 수 있으므로 audio bytes가 device를 떠나는지, 어떤 OS·meeting/prototype processor가 일시 처리하는지와 저장 여부를 data-flow sheet와 consent에 포함합니다.

이 standardized copy task는 method preference, correction interaction과 delayed retrieval을 비교하기 위한 controlled proxy입니다. 실제 순간에 스스로 기록할 필요가 생기는 spontaneous capture demand나 organic retention을 증명하지 않으며, `G-PROBLEM`의 past behavior와 분리해 해석합니다.

#### Session 2 — 24~48 Hours Later, 10~15 Minutes

1. Session 1 내용을 설명하거나 정답을 암시하지 않고 “Session 1에 text로 저장한 project의 표지 색과 검토 시각을 찾아 source를 확인해 주세요”와 “voice로 저장하고 교정한 project의 표지 색과 검토 시각을 current revision에서 찾아 주세요”를 정확히 한 번씩 제시합니다.
2. 홀수 participant는 voice item, 짝수 participant는 text item부터 수행합니다. voice result의 current/stale horizontal position은 홀수 participant에서 current-left, 짝수 participant에서 current-right로 고정합니다.
3. `G-TEXT`는 text card의 두 requested field와 source를, `G-VOICE-RECALL`은 voice card의 두 field와 current revision/source를 substantive hint 없이 정확히 선택해야 participant-level PASS입니다.
4. 어떤 capture method를 다음 동일 상황에서 선택할지 묻기 전에 두 delayed task를 완료합니다.
5. 마지막에 experience를 debrief하되 task 행동과 사후 설명을 서로 다른 evidence type으로 기록합니다.

Session 2 completion은 pre-booking과 standard reminder가 있는 delayed-task compliance와 source-grounded recall evidence이지 organic product retention evidence가 아닙니다. 시간 commitment는 연구 참여 evidence로만 기록하며 compensation, compliment와 general product interest를 product success signal로 세지 않습니다.

### Interview Script

facilitator는 80% 이상 듣고 pitch하지 않으며, future-intent 질문보다 past-tense specific example을 사용합니다.

#### Opening

- “오늘은 제품을 판매하는 자리가 아니라 최근 기록 습관과 두 가지 짧은 task에서 배우려는 자리입니다. 정답은 없습니다.”
- 수집 field, 녹음 기본값, 중단·철회와 삭제 방법을 설명하고 consent와 남은 시간을 확인합니다.
- “민감한 실제 내용은 말하지 말고 사람·회사·장소는 일반화해 주세요.”

#### Recent Behavior

- “가장 최근에 나중에 필요할 것 같아 무언가를 기록했던 때를 내용 없이 과정만 따라가 볼까요?”
- “어떤 surface를 어떤 순서로 썼고, 왜 그 방법을 골랐나요?”
- “하루 이상 지난 기록을 마지막으로 다시 찾았을 때 처음부터 끝까지 무슨 일이 있었나요?”
- “원하는 정보를 찾지 못했거나 맞는지 확신하기 어려웠던 최근 사례가 있나요? 그다음에는 어떻게 했나요?”
- “이 문제를 줄이려고 tool, sync, folder 또는 습관을 바꾼 적이 있나요? 실제로 무엇을 들였나요?”

#### Probes

- “그때의 구체적인 예를 하나 더 말해 줄 수 있나요?”
- “그다음에는 무슨 일이 있었나요?”
- “어떻게 확인했나요?”
- “얼마나 자주 실제로 일어나나요?”

`version`, `voice`, `source`, `privacy`, `local-first`와 purge option을 task 전에 먼저 말하지 않습니다. `이 앱을 쓰겠는가`처럼 expected answer를 포함하는 질문은 어느 단계에서도 하지 않습니다.

#### Post-task Debrief

- “세 capture에서 방법을 고르거나 바꾼 이유는 무엇인가요?”
- “두 comparison에서 각 time을 고른 이유는 무엇인가요?”
- “voice memo나 dictation을 실제로 마지막 사용한 때는 언제였고, 그 방법을 계속 쓰거나 중단한 이유는 무엇이었나요?”
- “기록 도구를 고를 때 가장 크게 고려했던 조건은 무엇이며, 그 조건 때문에 최근 실제 선택이나 설정을 바꾼 사례가 있나요?”

마지막 질문에 participant가 privacy 또는 직접 통제를 스스로 제시한 경우에만 “무엇을 바꿨고 어떤 시간·기능·편의 비용이 있었나요?”라고 구체화합니다. `G-LOCAL`은 이 중립 질문에서 나온 specific past behavior만 세고 “local-first가 중요한가”에 대한 동의는 세지 않습니다.

#### Wrap-up

- “빠뜨린 최근 행동이나 이 과정을 이해하는 데 중요한 점이 있나요?”
- “비슷한 문제를 실제로 겪는 분이 있다면 approved public invitation을 본인이 직접 전달해도 됩니다. 그분의 연락처는 알려 주지 마세요.”
- Session 2 window, 철회·삭제 방법과 raw research retention을 다시 확인합니다.

### Evidence Taxonomy And Traceability

외부 access-controlled raw dataset 안에서만 모든 evidence에 stable ID를 붙입니다.

- `P01-S1-EV-PAST-01`: interview에서 확인한 specific past behavior
- `P01-S1-EV-OBS-01`: walkthrough에서 직접 관찰한 behavior
- `P01-S1-EV-STATE-01`: policy 또는 사후 stated preference
- `P01-S2-EV-OBS-01`: delayed recall에서 직접 관찰한 behavior
- `P01-EV-FAULT-01`: facilitator intervention, technical fault 또는 exclusion fact

`EV-PAST`와 `EV-OBS`는 서로 대체하지 않고, `EV-STATE`만으로 behavior threshold를 통과시키지 않습니다. facilitator 해석은 observation과 분리합니다. raw evidence에는 최소한 아래 field만 둡니다.

```text
evidence_id:
plan_version: POV-022-v1
participant_id:
stratum: STR-VOICE | STR-TEXT
session: S1 | S2
evidence_type: EV-PAST | EV-OBS | EV-STATE | EV-FAULT
hypothesis_id: G-X | G-PROBLEM | G-VOICE | G-CORR | G-SRC | G-TEXT | G-VOICE-RECALL | G-QTEXT | G-A7 | G-LOCAL
task_or_prompt:
behavior_or_sanitized_paraphrase:
assistance: none | one-neutral-repeat | substantive
outcome: pass | fail | not-observed
contrary_evidence:
```

completed participant worksheet, contact, consent record, raw notes, participant/evidence ID와 participant-level paraphrase는 public repository에 넣지 않습니다. deletion 전에 authorized reviewer가 private ID에서 gate count까지 traceability를 확인하고 public decision record에는 `private traceability review: PASS|FAIL`만 남깁니다.

```markdown
| Gate | Required aggregate | Grouped supporting theme | Grouped contrary theme | Result |
| --- | --- | --- | --- | --- |
| G-X — primary joint loop | joint=TBD/6 | TBD | TBD | TBD |
| G-PROBLEM — recurring problem | pass=TBD/6 | TBD | TBD | TBD |
| G-VOICE — voice wedge | pass=TBD/6 | TBD | TBD | TBD |
| G-CORR — correction | pass=TBD/6 | TBD | TBD | TBD |
| G-SRC — source/revision display | labeled_current=TBD/6; hidden_current=TBD/6; delta=TBD | TBD | TBD | TBD |
| G-TEXT — delayed text loop | pass=TBD/6 | TBD | TBD | TBD |
| G-VOICE-RECALL — delayed corrected-voice loop | pass=TBD/6 | TBD | TBD | TBD |
| G-QTEXT — text-first narrow signal | joint=TBD/6 | TBD | TBD | TBD |
| G-A7 — default raw-audio policy | default_7d=TBD/6; immediate=TBD/6; export_then_purge=TBD/6; long_term_required=TBD/6 | TBD | TBD | TBD |
| G-LOCAL — local control segment | pass=TBD/6 | TBD | TBD | TBD |
```

public grouped theme는 participant 세 명 이상에게서 나타나고 identity, exact date, organization, location과 distinctive sequence를 제거한 경우에만 씁니다. 세 명 미만의 supporting/contrary detail은 count만 반영하고 `suppressed (<3)`로 표시하며, stratum별 count, direct quote와 cross-session individual linkage를 공개하지 않습니다. `TBD`를 synthetic participant result로 채우지 않습니다.

### Fixed Gates

각 numerator는 동일한 fixed denominator `6`을 사용합니다.

| Gate | Evidence type | PASS threshold |
| --- | --- | --- |
| `G-X` primary joint loop | same-participant observed task and delayed completion | 최소 4명의 동일 participant가 `G-VOICE`, `G-CORR`, participant-level labeled current choice와 `G-VOICE-RECALL`을 모두 PASS |
| `G-PROBLEM` recurring problem | specific past behavior | 최소 4명이 최근 fragmented capture와 하루 이상 지난 recall에서 material friction, failure 또는 workaround를 각각 구체 사례로 재현 |
| `G-VOICE` voice wedge | observed task | 최소 4명이 `CARD-A`/`CARD-B`의 text와 voice controlled capture를 모두 substantive content help 없이 완료한 뒤 `CARD-C` free-choice에서 voice를 선택 |
| `G-CORR` correction | observed task | 최소 4명이 exact seeded error를 substantive help 없이 원래 card 값으로 교정 |
| `G-SRC` source/revision display | counterbalanced matched task | 최소 4명이 labeled case에서 current v2를 선택하고, 전체 labeled current-choice 수가 hidden current-choice 수보다 최소 2 높음 |
| `G-TEXT` delayed text loop | observed delayed task | 최소 4명이 pre-booked Session 2에서 substantive hint 없이 text card의 두 field와 source를 정확히 확인 |
| `G-VOICE-RECALL` delayed corrected-voice loop | observed delayed task | 최소 4명이 pre-booked Session 2에서 substantive hint 없이 corrected voice card의 두 field와 current revision/source를 정확히 확인 |
| `G-QTEXT` text-first narrow signal | same-participant choice and delayed task | 최소 4명의 동일 participant가 free-choice `CARD-C`에서 text를 선택하고 `G-TEXT`도 PASS |
| `G-A7` raw-audio policy | stated policy choice | 최소 4명이 transcript 보존 조건의 exact 기본 7일 purge를 추가 export나 장기 raw 보존 요구 없이 선택하고, 장기 raw 보존이 필수인 participant는 최대 1명 |
| `G-LOCAL` local control segment | specific past behavior | 최소 4명이 privacy 또는 직접 통제를 위해 이미 tool choice, setup time, 기능 또는 편의를 실제로 바꾼 구체 사례를 제시 |

substantive help는 facilitator가 task의 내용, 정답, correction target, source 또는 revision 선택을 알려 주는 것입니다. 질문을 그대로 한 번 반복하거나 UI card 위치를 중립적으로 다시 가리키는 것은 `one-neutral-repeat`으로 기록하고 substantive help로 세지 않습니다.

`STR-VOICE`/`STR-TEXT`는 voice familiarity를 균형 있게 포함하기 위한 design block입니다. `n=3`인 stratum별 결과는 private diagnostic으로만 보고 public count나 decision threshold로 사용하지 않습니다. 특히 이 round만으로 “기존 voice 사용자만” 같은 segment narrow를 결정하지 않으며 그런 가설은 별도 preregistered sample이 필요합니다.

### Protocol Validity Precedence

product decision 전에 round validity를 먼저 판정합니다.

- approved execution manifest가 첫 outreach 전에 고정되고 모든 participant가 해당 data flow와 consent로 실행됩니다.
- allowed withdrawal/technical replacement 뒤 각 gate의 fixed denominator가 6이며 task copy, assignment, condition, order와 scoring key가 v1과 일치합니다.
- participant가 task method를 거부하거나 Session 2에 오지 않은 것은 withdrawal이 아닌 한 해당 behavior gate의 valid FAIL입니다. 반면 research-side tool/processor/data loss로 outcome을 관찰할 수 없으면 product FAIL로 바꾸지 않습니다.
- unconsented processing, unresolved safety incident, missing deletion contract 또는 research-side failure 때문에 gate를 fixed denominator로 판정할 수 없으면 round는 `INVALID`입니다.

`INVALID`는 다섯 번째 product outcome이 아니라 “결정 없음” 상태입니다. `proceed`/`narrow`/`pivot`/`stop`을 내리지 않고 H1을 계속 잠근 채 affected data를 consent와 retention rule에 따라 삭제하거나 격리하고, 새 plan/version review 뒤 새 round를 시작합니다.

### Decision Rule

| Decision | Pre-registered rule | Roadmap consequence |
| --- | --- | --- |
| `proceed` | valid round에서 `G-PROBLEM`, `G-TEXT`, `G-X`, `G-SRC`, `G-A7`, `G-LOCAL`이 모두 PASS | anonymized evidence와 decision을 기록한 뒤 POV-007을 Ready 후보로 review |
| `narrow — text-first` | valid round에서 `G-PROBLEM`, `G-TEXT`, `G-SRC`, `G-LOCAL`, `G-QTEXT`가 PASS하고 `G-X`는 FAIL | Product Strategy/WBS에서 H1 text foundation만 열고 voice/H2는 별도 evidence 전까지 gated |
| `narrow — retention` | valid round에서 `G-PROBLEM`, `G-TEXT`, `G-X`, `G-SRC`, `G-LOCAL`은 PASS, `G-A7`은 FAIL하며 최소 4명이 `즉시 purge` 또는 `explicit export 후 purge` 한 가지 alternative에 동일하게 수렴하고 장기 raw 보존 필수는 최대 1명 | Product Strategy와 affected retention ticket을 먼저 좁힌 뒤 H1 진입 여부 review |
| `pivot` | `G-PROBLEM`은 PASS하지만 `proceed`/`narrow` 조건을 충족하지 못하고, 최소 4명에게 반복되는 다른 job·solution pattern이 있음 | H1 delivery를 열지 않고 Product Strategy와 ADR-0003 재검토 |
| `stop` | `G-PROBLEM`이 FAIL하거나, `proceed`/`narrow` 조건을 충족하지 못하면서 최소 4명이 지지하는 viable alternative도 없음 | H1 delivery를 열지 않고 POV-022와 roadmap disposition 기록 |

`pivot`의 other pattern은 최소 4명의 서로 다른 participant가 제공한 `EV-PAST` 또는 `EV-OBS`에서 같은 trigger, desired outcome과 current action/workaround 조합이 반복될 때만 성립합니다. tool 이름만 같거나 compliment, `EV-STATE`, future intent와 facilitator interpretation만 같은 것은 합치지 않습니다. facilitator와 execution manifest에 등록된 independent reviewer가 private de-identified evidence를 각각 이 세 field로 coding하고, 두 사람이 같은 normalized pattern에 동의한 participant만 numerator에 넣습니다. unresolved disagreement는 pattern evidence로 세지 않습니다.

여러 rule에 걸치거나 evidence가 모호하면 더 적은 투자를 허용하는 `stop` < `pivot` < `narrow` < `proceed` 순서에서 낮은 상태를 선택합니다. threshold 또는 분모를 결과에 맞춰 바꾸지 않습니다.

valid product decision에는 early futility stop을 사용하지 않습니다. `G-PROBLEM` PASS가 수학적으로 불가능해져도 privacy/safety invalidation이 없는 한 여섯 participant denominator와 가능한 Session 2를 완료해 failure와 alternative pattern을 진단합니다.

### Consent, Privacy, Retention And Repository Safety

- 기본은 audio/video recording, auto-transcription, AI note와 prototype analytics 없음, facilitator minimal notes입니다. live voice를 transport하는 OS/meeting tool도 processor inventory에서 제외하지 않습니다. recording이 꼭 필요하면 별도 명시적 consent와 아래 external storage가 먼저 준비되어야 합니다.
- 실제 personal lifelog, transcript, voice, identity, employer, exact location, contact와 absolute local path를 public repository에 넣지 않습니다.
- participant가 민감한 내용을 말하면 facilitator는 중단하고 일반화하도록 요청하며 해당 raw detail을 note에 옮기지 않습니다. 이미 기록됐다면 즉시 redact하거나 삭제하고 `EV-FAULT` safety event만 비식별로 남깁니다.
- participant에게 random withdrawal code를 주고 그 code와 evidence ID의 mapping만 gate decision publication 때까지 별도 보관합니다. identity/contact와 연결하지 않습니다.
- consent withdrawal은 decision publication 전까지 participant가 withdrawal code를 제시하면 participant-level evidence 삭제와 같은 stratum replacement를 허용합니다. publication 뒤에는 contribution withdrawal cutoff가 지났고 mapping은 7일 안에 삭제되어 다시 찾을 수 없음을 consent 때 설명합니다.
- 적용 법률상 보존해야 하는 payment record는 research evidence와 분리하고 research decision에 사용하지 않습니다.

| Data | Primary, trash and version-history deletion | Unavoidable encrypted backup true maximum |
| --- | --- | --- |
| screened-out, declined, pre-Session-1 no-show contact/screener/recruitment/calendar metadata | disposition 뒤 7일 | disposition 뒤 37일 |
| enrolled contact/recruitment/calendar metadata | final session 또는 compensation 종료 뒤 7일 | 해당 종료 뒤 37일 |
| consented audio/video recording | session 뒤 7일 | session 뒤 37일 |
| withdrawal-code/evidence-ID mapping | decision publication 뒤 7일 이내이면서 Session 1 뒤 최대 90일 | primary deletion 뒤 30일 이내이면서 Session 1 뒤 최대 120일 |
| consent record, raw notes와 participant worksheet | decision publication 뒤 30일 이내이면서 Session 1 뒤 최대 90일; 90일까지 decision이 없으면 research 중단·삭제 | Session 1 뒤 최대 120일 |
| non-linkable public aggregate와 decision | project decision history로 보존 | repository backup policy |

backup을 사용하지 않는 것이 기본입니다. unavoidable backup은 primary deletion 뒤 최대 30일 안에 purge되는 contract만 허용하고 위 true maximum을 participant-facing consent에 그대로 알립니다.

- public repository에는 plan version, aggregate numerator/denominator, 3명 이상 non-linkable grouped theme, suppressed contrary count, decision과 변경된 strategy만 보존합니다. participant/evidence ID, participant-level paraphrase, direct quote와 소수 조합으로 재식별 가능한 demographic detail은 저장하지 않습니다.
- research를 시작하기 전에 저장소 밖의 exact access-controlled location, access owner, processor, backup/trash/version-history behavior와 deletion confirmation 방법을 사용자와 정해야 합니다. primary, trash, version history와 backup purge가 확인되지 않으면 삭제 완료로 기록하지 않습니다.

### External Execution Prerequisites

다음은 현재 저장소 작업으로 충족할 수 없는 blocker입니다.

- 실제 qualified participant 모집과 연락 권한
- recruitment channel, facilitator, 일정과 compensation 여부에 대한 사용자 결정
- private de-identified evidence를 coding할 independent reviewer와 authorized recipient 등록
- recruitment/screener/scheduling/session/voice/note tool의 processor와 retention을 포함한 participant-facing data-flow sheet
- raw consent/evidence용 exact access-controlled external storage, access owner와 backup/trash/version-history deletion contract
- 실제 consent, Session 1/2 observation과 participant behavior

recruitment message 전송, referral opt-in 연락, 일정 생성, cloud storage 생성·업로드, recording/auto-transcription 활성화와 compensation 지출은 각각 exact target, account, action과 비용을 사용자가 승인한 뒤에만 수행합니다. 이 goal은 그런 외부 action을 승인한 것으로 해석하지 않습니다.

이 prerequisite가 충족되기 전에는 POV-022 결과를 결정하거나 POV-007을 Ready로 바꾸지 않습니다.

## Acceptance Criteria

- [x] participant problem profile, sample, decision threshold와 stop rule이 research 시작 전에 기록됩니다.
- [ ] 현재 대안, capture friction, voice versus text preference와 later-recall need가 direct evidence로 구분됩니다.
- [ ] correction과 source/revision 표시가 trust와 행동에 미치는 반응이 관찰됩니다.
- [ ] accepted purge grace 밖의 raw audio 삭제 기대와 장기 보존 요구가 구분됩니다.
- [ ] private transcript, audio, identity와 absolute local path 없이 anonymized finding을 저장할 수 있습니다.
- [ ] 결과가 first segment와 voice wedge를 `proceed`, `narrow`, `pivot` 또는 `stop`으로 결정하고 Product Strategy/WBS 변경 여부를 명시합니다.

## Verification

- [x] pre-registered research plan and decision rule review
- [ ] interview/walkthrough/concierge evidence traceability
- [x] anonymization and public-repository safety review
- [x] strategy and roadmap readback
- [x] `git diff --check`

## Rollback

gate가 `pivot` 또는 `stop`이면 H1 delivery ticket을 Ready로 올리지 않습니다. Product Strategy, ADR-0003과 roadmap을 먼저 갱신하고 이미 완료된 reversible H0 foundation만 재사용 여부를 판단합니다.

participant research 시작 전에 v1을 폐기하면 폐기 이유를 기록하고 ticket/TODO를 `Ready`로 되돌릴 수 있습니다. 첫 Session 1 뒤에는 v1을 소급 수정하지 않고 current round를 중단한 다음 review된 v2로만 재시작합니다.

## Links

- [Product Strategy](../PRODUCT_STRATEGY.md)
- [Outcome Roadmap And WBS](../WBS.md)
- [ADR-0003](../decisions/0003-lifelogging-foundation-and-storyworld-follow-on.md)
- [POV-001](../deps/POV-001-local-offline-walking-skeleton.md)
- [POV-007](POV-007-local-login-refresh-and-session-revoke.md)
