/// <reference types="vitest/jsdom" />

// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  clearJobEventCursor,
  readJobEventCursor,
  readJobEventStream,
  runJobEventFeed,
  type JobStatusEvent,
} from './job-events.ts'

const encoder = new TextEncoder()

function event(cursor: string): JobStatusEvent {
  return {
    cursor,
    event_id: '11111111-1111-4111-8111-111111111111',
    job_id: '22222222-2222-4222-8222-222222222222',
    conversation_id: '44444444-4444-4444-8444-444444444444',
    source_event_id: '55555555-5555-4555-8555-555555555555',
    job_revision: Number(cursor),
    kind: 'succeeded',
    state: 'succeeded',
    attempt_id: null,
    happened_at_micros: '10000000',
    queue_wait_micros: '10',
    execution_micros: '20',
    failure_kind: null,
    correlation_id: '33333333-3333-4333-8333-333333333333',
  }
}

function streamFrom(chunks: string[]) {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk))
      controller.close()
    },
  })
}

function sseFrame(cursor: string) {
  return `event: job_status\r\nid: ${cursor}\r\ndata: ${JSON.stringify(event(cursor))}\r\n\r\n`
}

function feedOptions(signal: AbortSignal) {
  return {
    signal,
    getSession: () => ({
      access_token: 'synthetic-access-token',
      expires_at: 4_102_444_800,
    }),
    refreshSession: vi.fn().mockResolvedValue({
      access_token: 'rotated-synthetic-access-token',
      expires_at: 4_102_444_900,
    }),
    onAuthenticationLost: vi.fn(),
    onEvent: vi.fn(),
    onState: vi.fn(),
    onError: vi.fn(),
  }
}

describe('job event streaming client', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('parses chunked CRLF frames and heartbeat comments', async () => {
    const frames: unknown[] = []
    const heartbeat = vi.fn()
    const controller = new AbortController()
    const body = streamFrom([
      ': heart',
      'beat\r\n\r\nevent: job_status\r\nid: 17\r\n',
      `data: ${JSON.stringify(event('17'))}\r\n\r\n`,
    ])

    await readJobEventStream(
      body,
      controller.signal,
      (frame) => frames.push(frame),
      heartbeat,
    )

    expect(heartbeat).toHaveBeenCalledOnce()
    expect(frames).toEqual([
      {
        event: 'job_status',
        id: '17',
        data: JSON.stringify(event('17')),
      },
    ])
  })

  it('rejects a frame larger than 64 KiB', async () => {
    const controller = new AbortController()
    await expect(
      readJobEventStream(
        streamFrom([`data: ${'x'.repeat(64 * 1024)}\n\n`]),
        controller.signal,
        vi.fn(),
        vi.fn(),
      ),
    ).rejects.toThrow('64 KiB')
  })

  it('suppresses duplicate cursors and persists only the applied cursor', async () => {
    const controller = new AbortController()
    const options = feedOptions(controller.signal)
    options.onState.mockImplementation((state) => {
      if (state === 'reconnecting') controller.abort()
    })
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(streamFrom([sseFrame('17'), sseFrame('17')]), {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        }),
      ),
    )

    await runJobEventFeed(options)

    expect(options.onEvent).toHaveBeenCalledOnce()
    expect(readJobEventCursor()).toBe('17')
  })

  it('rejects mismatched frame and payload cursors without applying it', async () => {
    const controller = new AbortController()
    const options = feedOptions(controller.signal)
    options.onState.mockImplementation((state) => {
      if (state === 'reconnecting') controller.abort()
    })
    const mismatched = `event: job_status\nid: 18\ndata: ${JSON.stringify(event('17'))}\n\n`
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(streamFrom([mismatched]))),
    )

    await runJobEventFeed(options)

    expect(options.onEvent).not.toHaveBeenCalled()
    expect(options.onError).toHaveBeenCalled()
    expect(readJobEventCursor()).toBe('0')
  })

  it('rejects status events without owner-scoped conversation linkage', async () => {
    const controller = new AbortController()
    const options = feedOptions(controller.signal)
    options.onState.mockImplementation((state) => {
      if (state === 'reconnecting') controller.abort()
    })
    const malformed = event('17') as Partial<JobStatusEvent>
    delete malformed.conversation_id
    const frame = `event: job_status\nid: 17\ndata: ${JSON.stringify(malformed)}\n\n`
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(streamFrom([frame]))),
    )

    await runJobEventFeed(options)

    expect(options.onEvent).not.toHaveBeenCalled()
    expect(options.onError).toHaveBeenCalled()
    expect(readJobEventCursor()).toBe('0')
  })

  it('resets an invalid stored cursor once and stops on repeated rejection', async () => {
    window.sessionStorage.setItem('pov.job-events.cursor.v1', '17')
    const controller = new AbortController()
    const options = feedOptions(controller.signal)
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ error: 'invalid_cursor' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await runJobEventFeed(options)

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(clearJobEventCursor()).toBeUndefined()
    expect(readJobEventCursor()).toBe('0')
    expect(options.onError).toHaveBeenCalledWith(
      '저장된 상태 위치를 서버와 다시 맞추지 못했습니다.',
    )
  })

  it('falls back to one-second polling only when streaming is unavailable', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const options = feedOptions(controller.signal)
    options.onEvent.mockImplementation(() => controller.abort())
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 501 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            events: [event('21')],
            next_cursor: '21',
            has_more: false,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      )
    vi.stubGlobal('fetch', fetchMock)

    const run = runJobEventFeed(options)
    await vi.runAllTimersAsync()
    await run

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/jobs/events/stream')
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/api/jobs/events?after=0')
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      credentials: 'omit',
      cache: 'no-store',
    })
    expect(options.onState).toHaveBeenCalledWith('polling')
    expect(options.onEvent).toHaveBeenCalledWith(event('21'))
  })

  it('shares an early expiry refresh before opening the stream', async () => {
    const controller = new AbortController()
    const options = feedOptions(controller.signal)
    options.getSession = () => ({
      access_token: 'expiring-synthetic-access-token',
      expires_at: Math.floor(Date.now() / 1000) + 4,
    })
    const fetchMock = vi.fn().mockImplementation((_path, init: RequestInit) => {
      controller.abort()
      return Promise.reject(init.signal?.reason)
    })
    vi.stubGlobal('fetch', fetchMock)

    await runJobEventFeed(options)

    expect(options.refreshSession).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toEqual({
      Authorization: 'Bearer rotated-synthetic-access-token',
    })
  })
})
