export type JobStatusEvent = {
  cursor: string
  event_id: string
  job_id: string
  conversation_id: string
  source_event_id: string
  job_revision: number
  kind: string
  state: string
  attempt_id: string | null
  happened_at_micros: string
  queue_wait_micros: string | null
  execution_micros: string | null
  failure_kind: string | null
  correlation_id: string
}

export type JobEventPage = {
  events: JobStatusEvent[]
  next_cursor: string
  has_more: boolean
}

export type JobEventConnectionState =
  'connecting' | 'connected' | 'reconnecting' | 'polling'

export type JobEventSession = {
  access_token: string
  expires_at: number
}

type JobEventFeedOptions = {
  signal: AbortSignal
  getSession: () => JobEventSession
  refreshSession: () => Promise<JobEventSession>
  onAuthenticationLost: () => void
  onEvent: (event: JobStatusEvent) => void
  onState: (state: JobEventConnectionState) => void
  onError: (message: string) => void
}

type ParsedSseFrame = {
  event: string
  id: string
  data: string
}

const CURSOR_STORAGE_KEY = 'pov.job-events.cursor.v1'
const MAX_FRAME_BYTES = 64 * 1024
const MAX_CURSOR = BigInt('9223372036854775807')
const STREAM_BACKOFF_MS = [250, 500, 1000, 2000, 5000] as const
const POLL_INTERVAL_MS = 1000
const REFRESH_LEAD_MS = 5000
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const JOB_STATES = new Set([
  'queued',
  'leased',
  'running',
  'cancel_requested',
  'retry_scheduled',
  'waiting_confirmation',
  'recovery_required',
  'succeeded',
  'failed',
  'cancelled',
])
const JOB_FAILURES = new Set([
  'provider_unavailable',
  'timeout',
  'execution_failed',
  'lease_expired',
  'cleanup_uncertain',
])

export function clearJobEventCursor() {
  window.sessionStorage.removeItem(CURSOR_STORAGE_KEY)
}

export function readJobEventCursor() {
  const stored = window.sessionStorage.getItem(CURSOR_STORAGE_KEY)
  if (stored !== null && isCanonicalCursor(stored)) return stored
  if (stored !== null) clearJobEventCursor()
  return '0'
}

export function isCanonicalCursor(value: unknown): value is string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    return false
  }
  try {
    return BigInt(value) <= MAX_CURSOR
  } catch {
    return false
  }
}

function storeCursor(cursor: string) {
  window.sessionStorage.setItem(CURSOR_STORAGE_KEY, cursor)
}

function statusOf(error: unknown) {
  if (
    typeof error === 'object' &&
    error !== null &&
    'status' in error &&
    typeof error.status === 'number'
  ) {
    return error.status
  }
  return undefined
}

async function refreshOrEnd(options: JobEventFeedOptions) {
  try {
    return await options.refreshSession()
  } catch (error) {
    if (statusOf(error) === 401) {
      clearJobEventCursor()
      options.onAuthenticationLost()
      return undefined
    }
    options.onError('상태 연결을 위한 세션 갱신에 실패했습니다.')
    throw error
  }
}

function millisecondsUntilRefresh(session: JobEventSession) {
  return session.expires_at * 1000 - Date.now() - REFRESH_LEAD_MS
}

async function sessionReadyForRequest(options: JobEventFeedOptions) {
  let session = options.getSession()
  if (millisecondsUntilRefresh(session) <= 0) {
    const refreshed = await refreshOrEnd(options)
    if (!refreshed) return undefined
    session = refreshed
  }
  return session
}

function abortableDelay(milliseconds: number, signal: AbortSignal) {
  if (signal.aborted) return Promise.resolve()
  return new Promise<void>((resolve) => {
    const timeout = window.setTimeout(done, milliseconds)
    signal.addEventListener('abort', done, { once: true })
    function done() {
      window.clearTimeout(timeout)
      signal.removeEventListener('abort', done)
      resolve()
    }
  })
}

function appendBytes(left: Uint8Array, right: Uint8Array) {
  if (left.length === 0) return right.slice()
  const joined = new Uint8Array(left.length + right.length)
  joined.set(left)
  joined.set(right, left.length)
  return joined
}

function frameBoundary(bytes: Uint8Array) {
  for (let index = 0; index < bytes.length - 1; index += 1) {
    if (bytes[index] === 10 && bytes[index + 1] === 10) {
      return { index, length: 2 }
    }
    if (bytes[index] === 13 && bytes[index + 1] === 13) {
      return { index, length: 2 }
    }
    if (
      index < bytes.length - 3 &&
      bytes[index] === 13 &&
      bytes[index + 1] === 10 &&
      bytes[index + 2] === 13 &&
      bytes[index + 3] === 10
    ) {
      return { index, length: 4 }
    }
  }
  return undefined
}

function parseFrame(frameBytes: Uint8Array): ParsedSseFrame | 'heartbeat' {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(frameBytes)
  const lines = text.replace(/\r\n?/g, '\n').split('\n')
  let event = ''
  let id = ''
  const data: string[] = []
  let comment = false
  for (const line of lines) {
    if (line.startsWith(':')) {
      comment = true
      continue
    }
    const separator = line.indexOf(':')
    const field = separator === -1 ? line : line.slice(0, separator)
    let value = separator === -1 ? '' : line.slice(separator + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'event') {
      if (event) throw new Error('duplicate SSE event field')
      event = value
    } else if (field === 'id') {
      if (id) throw new Error('duplicate SSE id field')
      id = value
    } else if (field === 'data') {
      data.push(value)
    }
  }
  if (comment && !event && !id && data.length === 0) return 'heartbeat'
  if (event !== 'job_status' || !id || data.length === 0) {
    throw new Error('invalid job status SSE frame')
  }
  return { event, id, data: data.join('\n') }
}

export async function readJobEventStream(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
  onFrame: (frame: ParsedSseFrame) => void,
  onHeartbeat: () => void,
) {
  const reader = body.getReader()
  let pending = new Uint8Array()
  const abort = () => void reader.cancel()
  signal.addEventListener('abort', abort, { once: true })
  try {
    while (!signal.aborted) {
      const result = await reader.read()
      if (result.done) break
      pending = appendBytes(pending, result.value)
      let boundary = frameBoundary(pending)
      while (boundary) {
        if (boundary.index > MAX_FRAME_BYTES) {
          throw new Error('job status SSE frame exceeds 64 KiB')
        }
        const parsed = parseFrame(pending.slice(0, boundary.index))
        pending = pending.slice(boundary.index + boundary.length)
        if (parsed === 'heartbeat') onHeartbeat()
        else onFrame(parsed)
        boundary = frameBoundary(pending)
      }
      if (pending.length > MAX_FRAME_BYTES) {
        throw new Error('job status SSE frame exceeds 64 KiB')
      }
    }
    if (!signal.aborted && pending.length !== 0) {
      throw new Error('truncated job status SSE frame')
    }
  } finally {
    signal.removeEventListener('abort', abort)
    reader.releaseLock()
  }
}

function parseJobStatusEvent(value: unknown): JobStatusEvent {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('cursor' in value) ||
    !isCanonicalCursor(value.cursor) ||
    !('event_id' in value) ||
    typeof value.event_id !== 'string' ||
    !UUID_V4.test(value.event_id) ||
    !('job_id' in value) ||
    typeof value.job_id !== 'string' ||
    !UUID_V4.test(value.job_id) ||
    !('conversation_id' in value) ||
    typeof value.conversation_id !== 'string' ||
    !UUID_V4.test(value.conversation_id) ||
    !('source_event_id' in value) ||
    typeof value.source_event_id !== 'string' ||
    !UUID_V4.test(value.source_event_id) ||
    !('job_revision' in value) ||
    typeof value.job_revision !== 'number' ||
    !Number.isSafeInteger(value.job_revision) ||
    value.job_revision < 1 ||
    !('kind' in value) ||
    typeof value.kind !== 'string' ||
    !('state' in value) ||
    typeof value.state !== 'string' ||
    !JOB_STATES.has(value.state) ||
    !('attempt_id' in value) ||
    !(
      value.attempt_id === null ||
      (typeof value.attempt_id === 'string' && UUID_V4.test(value.attempt_id))
    ) ||
    !('happened_at_micros' in value) ||
    !isCanonicalCursor(value.happened_at_micros) ||
    !('queue_wait_micros' in value) ||
    !isNullableCanonicalCursor(value.queue_wait_micros) ||
    !('execution_micros' in value) ||
    !isNullableCanonicalCursor(value.execution_micros) ||
    !('failure_kind' in value) ||
    !(
      value.failure_kind === null ||
      (typeof value.failure_kind === 'string' &&
        JOB_FAILURES.has(value.failure_kind))
    ) ||
    !('correlation_id' in value) ||
    typeof value.correlation_id !== 'string' ||
    !UUID_V4.test(value.correlation_id)
  ) {
    throw new Error('invalid job status event')
  }
  return value as JobStatusEvent
}

function isNullableCanonicalCursor(value: unknown) {
  return value === null || isCanonicalCursor(value)
}

function parseJobEventPage(value: unknown): JobEventPage {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('events' in value) ||
    !Array.isArray(value.events) ||
    !('next_cursor' in value) ||
    !isCanonicalCursor(value.next_cursor) ||
    !('has_more' in value) ||
    typeof value.has_more !== 'boolean'
  ) {
    throw new Error('invalid job event page')
  }
  return {
    events: value.events.map(parseJobStatusEvent),
    next_cursor: value.next_cursor,
    has_more: value.has_more,
  }
}

function applyEvent(
  frameId: string,
  event: JobStatusEvent,
  cursor: string,
  options: JobEventFeedOptions,
) {
  if (!isCanonicalCursor(frameId) || frameId !== event.cursor) {
    throw new Error('job status frame cursor mismatch')
  }
  if (BigInt(frameId) <= BigInt(cursor)) return cursor
  options.onEvent(event)
  storeCursor(frameId)
  return frameId
}

async function handleInvalidCursor(
  resetUsed: boolean,
  options: JobEventFeedOptions,
) {
  if (resetUsed) {
    options.onError('저장된 상태 위치를 서버와 다시 맞추지 못했습니다.')
    return false
  }
  clearJobEventCursor()
  return true
}

async function runPolling(
  initialCursor: string,
  resetUsed: boolean,
  options: JobEventFeedOptions,
) {
  let cursor = initialCursor
  let didReset = resetUsed
  options.onState('polling')
  while (!options.signal.aborted) {
    const session = await sessionReadyForRequest(options)
    if (!session) return
    let response: Response
    try {
      response = await fetch(`/api/jobs/events?after=${cursor}`, {
        credentials: 'omit',
        cache: 'no-store',
        headers: { Authorization: `Bearer ${session.access_token}` },
        signal: options.signal,
      })
    } catch {
      if (options.signal.aborted) return
      options.onError('상태 polling 연결이 끊겨 다시 시도합니다.')
      await abortableDelay(POLL_INTERVAL_MS, options.signal)
      continue
    }
    if (response.status === 401) {
      if (!(await refreshOrEnd(options))) return
      continue
    }
    if (response.status === 400) {
      const payload = (await response.json().catch(() => ({}))) as {
        error?: unknown
      }
      if (payload.error === 'invalid_cursor') {
        if (!(await handleInvalidCursor(didReset, options))) return
        didReset = true
        cursor = '0'
        continue
      }
    }
    if (!response.ok) {
      options.onError('상태 저장소를 확인하지 못해 polling을 재시도합니다.')
      await abortableDelay(POLL_INTERVAL_MS, options.signal)
      continue
    }
    const page = parseJobEventPage(await response.json())
    for (const event of page.events) {
      cursor = applyEvent(event.cursor, event, cursor, options)
    }
    if (page.next_cursor !== cursor) {
      throw new Error('job event page cursor mismatch')
    }
    if (!page.has_more) {
      await abortableDelay(POLL_INTERVAL_MS, options.signal)
    }
  }
}

export async function runJobEventFeed(options: JobEventFeedOptions) {
  let cursor = readJobEventCursor()
  let resetUsed = false
  let backoffIndex = 0
  options.onState('connecting')

  while (!options.signal.aborted) {
    const session = await sessionReadyForRequest(options)
    if (!session) return
    const requestController = new AbortController()
    const abortRequest = () => requestController.abort()
    options.signal.addEventListener('abort', abortRequest, { once: true })
    let refreshDue = false
    const refreshDelay = Math.max(
      0,
      Math.min(millisecondsUntilRefresh(session), 2_147_483_647),
    )
    const refreshTimeout = window.setTimeout(() => {
      refreshDue = true
      requestController.abort()
    }, refreshDelay)
    let response: Response
    try {
      const headers: Record<string, string> = {
        Authorization: `Bearer ${session.access_token}`,
      }
      if (cursor !== '0') headers['Last-Event-ID'] = cursor
      response = await fetch('/api/jobs/events/stream', {
        credentials: 'omit',
        cache: 'no-store',
        headers,
        signal: requestController.signal,
      })
    } catch {
      window.clearTimeout(refreshTimeout)
      options.signal.removeEventListener('abort', abortRequest)
      if (options.signal.aborted) return
      if (refreshDue) {
        if (!(await refreshOrEnd(options))) return
        continue
      }
      options.onState('reconnecting')
      await abortableDelay(
        STREAM_BACKOFF_MS[Math.min(backoffIndex, STREAM_BACKOFF_MS.length - 1)],
        options.signal,
      )
      backoffIndex += 1
      continue
    }

    if (response.status === 401) {
      window.clearTimeout(refreshTimeout)
      options.signal.removeEventListener('abort', abortRequest)
      if (!(await refreshOrEnd(options))) return
      continue
    }
    if (response.status === 400) {
      window.clearTimeout(refreshTimeout)
      options.signal.removeEventListener('abort', abortRequest)
      const payload = (await response.json().catch(() => ({}))) as {
        error?: unknown
      }
      if (payload.error === 'invalid_cursor') {
        if (!(await handleInvalidCursor(resetUsed, options))) return
        resetUsed = true
        cursor = '0'
        continue
      }
    }
    if (
      response.status === 404 ||
      response.status === 501 ||
      (response.ok && response.body === null)
    ) {
      window.clearTimeout(refreshTimeout)
      options.signal.removeEventListener('abort', abortRequest)
      requestController.abort()
      await runPolling(cursor, resetUsed, options)
      return
    }
    if (!response.ok || response.body === null) {
      window.clearTimeout(refreshTimeout)
      options.signal.removeEventListener('abort', abortRequest)
      options.onError('실시간 상태 저장소를 확인하지 못해 다시 연결합니다.')
      options.onState('reconnecting')
      await abortableDelay(
        STREAM_BACKOFF_MS[Math.min(backoffIndex, STREAM_BACKOFF_MS.length - 1)],
        options.signal,
      )
      backoffIndex += 1
      continue
    }

    options.onState('connected')
    try {
      await readJobEventStream(
        response.body,
        requestController.signal,
        (frame) => {
          const event = parseJobStatusEvent(JSON.parse(frame.data))
          cursor = applyEvent(frame.id, event, cursor, options)
          backoffIndex = 0
        },
        () => {
          backoffIndex = 0
        },
      )
    } catch {
      if (!requestController.signal.aborted) {
        options.onError('실시간 상태 응답을 해석하지 못해 다시 연결합니다.')
      }
    } finally {
      window.clearTimeout(refreshTimeout)
      options.signal.removeEventListener('abort', abortRequest)
      requestController.abort()
    }
    if (options.signal.aborted) return
    if (refreshDue) {
      if (!(await refreshOrEnd(options))) return
      continue
    }
    options.onState('reconnecting')
    await abortableDelay(
      STREAM_BACKOFF_MS[Math.min(backoffIndex, STREAM_BACKOFF_MS.length - 1)],
      options.signal,
    )
    backoffIndex += 1
  }
}
