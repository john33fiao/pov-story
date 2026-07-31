import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'

import {
  ApiError,
  appendUserEvent,
  listConversations,
  login,
  logout,
  readConversation,
  refreshSession,
  type ConversationSummary,
  type ConversationTimeline,
  type Session,
} from './api.ts'
import {
  clearJobEventCursor,
  runJobEventFeed,
  type JobEventConnectionState,
} from './job-events.ts'

type Phase = 'booting' | 'anonymous' | 'authenticated'

let bootstrapSession: Promise<Session> | undefined

function restoreSessionOnce() {
  bootstrapSession ??= refreshSession()
  return bootstrapSession
}

function messageFor(error: unknown) {
  if (!(error instanceof ApiError)) {
    return '로컬 서버에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.'
  }
  switch (error.code) {
    case 'invalid_credentials':
      return '로그인 정보가 일치하지 않습니다.'
    case 'authentication_unavailable':
      return '인증을 잠시 사용할 수 없습니다.'
    case 'invalid_token':
    case 'invalid_session':
      return '세션이 만료되었습니다. 다시 로그인해 주세요.'
    case 'invalid_request':
      return '요청 형식을 확인해 주세요.'
    case 'request_rejected':
      return '로컬 요청의 보안 조건을 확인하지 못했습니다.'
    case 'revision_conflict':
      return '다른 변경이 먼저 저장되었습니다. 대화를 다시 불러와 주세요.'
    case 'idempotency_conflict':
      return '같은 요청 키가 다른 내용에 사용되었습니다.'
    case 'content_too_large':
      return '한 번에 저장할 수 있는 글자 수를 초과했습니다.'
    case 'invalid_content':
      return '내용을 입력해 주세요.'
    case 'storage_unavailable':
      return '기록 저장소를 잠시 사용할 수 없습니다.'
    default:
      return '요청을 완료하지 못했습니다. 다시 시도해 주세요.'
  }
}

function shortId(value: string) {
  return value.slice(0, 8)
}

export default function App() {
  const [phase, setPhase] = useState<Phase>('booting')
  const [loginId, setLoginId] = useState('')
  const [password, setPassword] = useState('')
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [timeline, setTimeline] = useState<ConversationTimeline>()
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  const [status, setStatus] = useState('로컬 세션을 확인하고 있습니다.')
  const [connectionStatus, setConnectionStatus] = useState('상태 연결 준비 중')
  const [busy, setBusy] = useState(false)
  const accessToken = useRef('')
  const sessionRef = useRef<Session | undefined>(undefined)
  const refreshInFlight = useRef<Promise<Session> | undefined>(undefined)

  const acceptSession = useCallback((session: Session, announce = true) => {
    accessToken.current = session.access_token
    sessionRef.current = session
    setPhase('authenticated')
    if (announce) setStatus('이 장치의 기록에 연결되었습니다.')
  }, [])

  const endSession = useCallback(() => {
    accessToken.current = ''
    sessionRef.current = undefined
    clearJobEventCursor()
    setConversations([])
    setTimeline(undefined)
    setPhase('anonymous')
  }, [])

  useEffect(() => {
    let active = true
    void restoreSessionOnce()
      .then((session) => {
        if (active) acceptSession(session)
      })
      .catch(() => {
        if (active) {
          endSession()
          setStatus('로그인이 필요합니다.')
        }
      })
    return () => {
      active = false
    }
  }, [acceptSession, endSession])

  const refreshAccess = useCallback(async () => {
    const refresh =
      refreshInFlight.current ??
      refreshSession().finally(() => {
        refreshInFlight.current = undefined
      })
    refreshInFlight.current = refresh
    try {
      const refreshed = await refresh
      acceptSession(refreshed, false)
      return refreshed
    } catch (refreshError) {
      if (refreshError instanceof ApiError && refreshError.status === 401) {
        endSession()
      }
      throw refreshError
    }
  }, [acceptSession, endSession])

  const withAccess = useCallback(
    async <T,>(operation: (token: string) => Promise<T>): Promise<T> => {
      try {
        return await operation(accessToken.current)
      } catch (operationError) {
        if (
          !(operationError instanceof ApiError) ||
          operationError.status !== 401
        ) {
          throw operationError
        }
        const refreshed = await refreshAccess()
        return operation(refreshed.access_token)
      }
    },
    [refreshAccess],
  )

  const loadConversations = useCallback(async () => {
    const items = await withAccess(listConversations)
    setConversations(items)
    return items
  }, [withAccess])

  useEffect(() => {
    if (phase !== 'authenticated') return
    let active = true
    void loadConversations()
      .then((items) => {
        if (active) {
          setStatus(
            items.length === 0
              ? '첫 기록을 시작할 준비가 되었습니다.'
              : `${items.length}개의 기록을 불러왔습니다.`,
          )
        }
      })
      .catch((loadError) => {
        if (active) setError(messageFor(loadError))
      })
    return () => {
      active = false
    }
  }, [loadConversations, phase])

  useEffect(() => {
    if (phase !== 'authenticated') return
    const controller = new AbortController()
    const stateText: Record<JobEventConnectionState, string> = {
      connecting: '상태 연결 중',
      connected: '실시간 상태 연결됨',
      reconnecting: '상태 다시 연결 중',
      polling: '상태 polling 중',
    }
    void runJobEventFeed({
      signal: controller.signal,
      getSession: () => {
        if (!sessionRef.current)
          throw new Error('authenticated session missing')
        return sessionRef.current
      },
      refreshSession: refreshAccess,
      onAuthenticationLost: endSession,
      onEvent: () => {},
      onState: (nextState) => setConnectionStatus(stateText[nextState]),
      onError: (message) => setConnectionStatus(message),
    }).catch(() => {
      if (!controller.signal.aborted) {
        setConnectionStatus('상태 연결을 계속할 수 없습니다.')
      }
    })
    return () => {
      controller.abort()
    }
  }, [endSession, phase, refreshAccess])

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      clearJobEventCursor()
      acceptSession(await login(loginId, password))
    } catch (loginError) {
      setError(messageFor(loginError))
    } finally {
      setPassword('')
      setBusy(false)
    }
  }

  async function handleLogout() {
    setBusy(true)
    setError('')
    let revoked = false
    try {
      await logout()
      revoked = true
    } catch {
      setError(
        '로컬 액세스는 지웠지만 서버 세션 폐기를 확인하지 못했습니다. 페이지를 다시 열기 전에 서버 상태를 확인해 주세요.',
      )
    } finally {
      bootstrapSession = undefined
      endSession()
      setStatus(
        revoked
          ? '로그아웃했습니다.'
          : '이 화면의 액세스만 종료했습니다. 서버 세션 상태는 미확인입니다.',
      )
      setBusy(false)
    }
  }

  async function openConversation(conversationId: string) {
    setBusy(true)
    setError('')
    try {
      const selected = await withAccess((token) =>
        readConversation(token, conversationId),
      )
      setTimeline(selected)
      setStatus(`기록 ${shortId(conversationId)}을 불러왔습니다.`)
    } catch (openError) {
      setError(messageFor(openError))
    } finally {
      setBusy(false)
    }
  }

  function startConversation() {
    const conversationId = crypto.randomUUID()
    setTimeline({ conversation_id: conversationId, revision: 0, events: [] })
    setDraft('')
    setError('')
    setStatus('새 기록입니다. 첫 문장을 남겨 보세요.')
  }

  async function handleAppend(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!timeline || draft.trim().length === 0) {
      setError('내용을 입력해 주세요.')
      return
    }
    const content = draft
    const conversationId = timeline.conversation_id
    const expectedRevision =
      timeline.revision === 0 ? undefined : timeline.revision
    const idempotencyKey = crypto.randomUUID()
    setBusy(true)
    setError('')
    setStatus('이 장치에 기록하고 있습니다.')
    try {
      const updated = await withAccess((token) =>
        appendUserEvent(
          token,
          conversationId,
          idempotencyKey,
          expectedRevision,
          content,
        ),
      )
      setTimeline(updated)
      setDraft('')
      await loadConversations()
      setStatus(`리비전 ${updated.revision}까지 안전하게 기록했습니다.`)
    } catch (appendError) {
      setError(messageFor(appendError))
      setStatus('기록을 저장하지 못했습니다.')
    } finally {
      setBusy(false)
    }
  }

  if (phase === 'booting') {
    return (
      <main className="centered-shell" aria-busy="true">
        <p className="eyebrow">POV STORY</p>
        <h1>로컬 기록을 여는 중</h1>
        <p className="muted" role="status">
          {status}
        </p>
      </main>
    )
  }

  if (phase === 'anonymous') {
    return (
      <main className="centered-shell">
        <section className="login-card" aria-labelledby="login-title">
          <p className="eyebrow">LOCAL-FIRST LIFELOG</p>
          <h1 id="login-title">내 기록으로 돌아가기</h1>
          <p className="muted">
            인증 정보는 이 로컬 앱에만 전송되며, 액세스 토큰은 페이지 메모리에만
            유지됩니다.
          </p>
          <form className="login-form" onSubmit={handleLogin}>
            <label htmlFor="login-id">로그인 ID</label>
            <input
              id="login-id"
              name="username"
              autoComplete="username"
              value={loginId}
              onChange={(event) => setLoginId(event.target.value)}
              required
            />
            <label htmlFor="password">비밀번호</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
            <button className="primary-button" type="submit" disabled={busy}>
              {busy ? '확인 중…' : '로그인'}
            </button>
          </form>
          <p className="status-text" role="status">
            {status}
          </p>
          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}
        </section>
      </main>
    )
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            P
          </span>
          <span>
            <strong>POV Story</strong>
            <small>Local text journal</small>
          </span>
        </div>
        <div className="session-actions">
          <span className="connection-status">{connectionStatus}</span>
          <button
            className="quiet-button"
            type="button"
            disabled={busy}
            onClick={() => void handleLogout()}
          >
            로그아웃
          </button>
        </div>
      </header>

      <aside className="conversation-sidebar" aria-label="기록 목록">
        <div className="sidebar-heading">
          <div>
            <p className="eyebrow">TIMELINE</p>
            <h2>내 기록</h2>
          </div>
          <button
            className="new-button"
            type="button"
            onClick={startConversation}
            disabled={busy}
          >
            새 기록
          </button>
        </div>
        <nav aria-label="저장된 기록">
          {conversations.length === 0 ? (
            <p className="empty-list">아직 저장된 기록이 없습니다.</p>
          ) : (
            <ul className="conversation-list">
              {conversations.map((conversation) => (
                <li key={conversation.conversation_id}>
                  <button
                    type="button"
                    className={
                      timeline?.conversation_id === conversation.conversation_id
                        ? 'conversation-button selected'
                        : 'conversation-button'
                    }
                    aria-current={
                      timeline?.conversation_id === conversation.conversation_id
                        ? 'page'
                        : undefined
                    }
                    onClick={() =>
                      void openConversation(conversation.conversation_id)
                    }
                    disabled={busy}
                  >
                    <span>기록 {shortId(conversation.conversation_id)}</span>
                    <small>리비전 {conversation.revision}</small>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </nav>
      </aside>

      <main className="conversation-main">
        {!timeline ? (
          <section className="welcome-panel" aria-labelledby="welcome-title">
            <p className="eyebrow">ONE PRIVATE THREAD</p>
            <h1 id="welcome-title">지금의 맥락을 남겨 두세요.</h1>
            <p className="muted">
              저장된 기록을 열거나 새 기록을 시작할 수 있습니다. 이 단계에서는
              텍스트가 로컬 저장소에 안전하게 남는 흐름에 집중합니다.
            </p>
            <button
              className="primary-button compact"
              type="button"
              onClick={startConversation}
            >
              첫 기록 시작
            </button>
          </section>
        ) : (
          <section className="timeline-panel" aria-labelledby="timeline-title">
            <header className="timeline-heading">
              <div>
                <p className="eyebrow">PRIVATE RECORD</p>
                <h1 id="timeline-title">
                  기록 {shortId(timeline.conversation_id)}
                </h1>
              </div>
              <span className="revision-badge">rev {timeline.revision}</span>
            </header>

            <div className="event-stream" role="log" aria-live="polite">
              {timeline.events.length === 0 ? (
                <p className="empty-timeline">
                  첫 문장이 이 기록의 시작점이 됩니다.
                </p>
              ) : (
                timeline.events.map((item) => (
                  <article className="event-card" key={item.event_id}>
                    <div className="event-meta">
                      <span>
                        {item.kind === 'user_text' ? '나의 기록' : item.kind}
                      </span>
                      <span>#{item.revision}</span>
                    </div>
                    <p>{item.content}</p>
                  </article>
                ))
              )}
            </div>

            <form className="composer" onSubmit={handleAppend}>
              <label className="visually-hidden" htmlFor="composer-text">
                기록할 내용
              </label>
              <textarea
                id="composer-text"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder="지금 생각하고 있는 것을 적어 보세요."
                rows={4}
                maxLength={65_536}
                disabled={busy}
                required
              />
              <div className="composer-actions">
                <span>로컬 저장 · 최대 64 KiB</span>
                <button
                  className="primary-button compact"
                  type="submit"
                  disabled={busy || draft.trim().length === 0}
                >
                  {busy ? '기록 중…' : '기록하기'}
                </button>
              </div>
            </form>
          </section>
        )}

        <div className="announcements">
          <p className="status-text" role="status">
            {status}
          </p>
          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}
        </div>
      </main>
    </div>
  )
}
