export type Session = {
  access_token: string
  token_type: 'Bearer'
  expires_at: number
}

export type ConversationSummary = {
  conversation_id: string
  revision: number
}

export type ConversationEvent = {
  event_id: string
  revision: number
  kind: 'user_text' | 'assistant_text' | 'tool_call' | 'tool_result'
  content: string
  correlation_id: string
}

export type ConversationTimeline = {
  conversation_id: string
  revision: number
  events: ConversationEvent[]
  generation_jobs: GenerationJob[]
}

export type GenerationJobState =
  | 'queued'
  | 'leased'
  | 'running'
  | 'cancel_requested'
  | 'retry_scheduled'
  | 'waiting_confirmation'
  | 'recovery_required'
  | 'succeeded'
  | 'failed'
  | 'cancelled'

export type GenerationFailureKind =
  | 'provider_unavailable'
  | 'timeout'
  | 'execution_failed'
  | 'lease_expired'
  | 'cleanup_uncertain'

export type GenerationJob = {
  job_id: string
  source_outbox_id: string
  conversation_id: string
  source_event_id: string
  kind: 'conversation_response_v1'
  state: GenerationJobState
  revision: number
  attempts_started: number
  max_attempts: number
  queue_wait_micros: string
  execution_micros: string
  failure_kind: GenerationFailureKind | null
}

type ApiErrorPayload = {
  error?: unknown
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string) {
    super(code)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

const mutationHeaders = {
  'Content-Type': 'application/json',
  'X-POV-CSRF': '1',
} as const

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...init,
  })
  const payload = (await response.json().catch(() => ({}))) as ApiErrorPayload
  if (!response.ok) {
    const code =
      typeof payload.error === 'string' ? payload.error : 'request_failed'
    throw new ApiError(response.status, code)
  }
  return payload as T
}

export function refreshSession(): Promise<Session> {
  return requestJson('/api/auth/refresh', {
    method: 'POST',
    headers: mutationHeaders,
    body: '{}',
  })
}

export function login(loginId: string, password: string): Promise<Session> {
  return requestJson('/api/auth/login', {
    method: 'POST',
    headers: mutationHeaders,
    body: JSON.stringify({
      login_attempt_id: crypto.randomUUID(),
      login_id: loginId,
      password,
    }),
  })
}

export function logout(): Promise<{ error: string }> {
  return requestJson('/api/auth/logout', {
    method: 'POST',
    headers: mutationHeaders,
    body: '{}',
  })
}

export async function listConversations(
  accessToken: string,
): Promise<ConversationSummary[]> {
  const response = await requestJson<{ conversations: ConversationSummary[] }>(
    '/api/conversations',
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  )
  return response.conversations
}

export function readConversation(
  accessToken: string,
  conversationId: string,
): Promise<ConversationTimeline> {
  return requestJson(
    `/api/conversations/${encodeURIComponent(conversationId)}`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  )
}

export function appendUserEvent(
  accessToken: string,
  conversationId: string,
  idempotencyKey: string,
  expectedRevision: number | undefined,
  content: string,
): Promise<ConversationTimeline> {
  return requestJson(
    `/api/conversations/${encodeURIComponent(conversationId)}/events`,
    {
      method: 'POST',
      headers: {
        ...mutationHeaders,
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        idempotency_key: idempotencyKey,
        expected_revision: expectedRevision,
        content,
      }),
    },
  )
}

export function cancelGenerationJob(
  accessToken: string,
  jobId: string,
  expectedRevision: number,
  idempotencyKey: string,
): Promise<{ job: GenerationJob; replayed: boolean }> {
  return requestJson(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST',
    headers: {
      ...mutationHeaders,
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      idempotency_key: idempotencyKey,
      expected_revision: expectedRevision,
    }),
  })
}
