/// <reference types="vitest/jsdom" />

// @vitest-environment jsdom

import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('./job-events.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./job-events.ts')>()
  return {
    ...actual,
    runJobEventFeed: vi.fn().mockResolvedValue(undefined),
  }
})

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

async function renderFreshApp() {
  const { default: App } = await import('./App.tsx')
  return render(<App />)
}

describe('minimal authenticated local text chat', () => {
  beforeEach(() => {
    vi.resetModules()
    jsdom.window.localStorage.clear()
    jsdom.window.sessionStorage.clear()
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('falls back to the labelled login form without persisting tokens', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(401, { error: 'invalid_session' }))
    vi.stubGlobal('fetch', fetchMock)

    await renderFreshApp()

    expect(
      await screen.findByRole('heading', { name: '내 기록으로 돌아가기' }),
    ).toBeTruthy()
    expect(screen.getByLabelText('로그인 ID')).toBeTruthy()
    expect(screen.getByLabelText('비밀번호')).toBeTruthy()
    expect(jsdom.window.localStorage).toHaveLength(0)
    expect(jsdom.window.sessionStorage).toHaveLength(0)
  })

  it('omits the initial revision and renders only the authoritative readback', async () => {
    const conversationId = '47c0d72f-8cc0-4a57-8232-8b38547ca710'
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          access_token: 'synthetic-access-token',
          token_type: 'Bearer',
          expires_at: 4_102_444_800,
        }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { conversations: [] }))
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid_token' }))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          access_token: 'rotated-synthetic-access-token',
          token_type: 'Bearer',
          expires_at: 4_102_444_900,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          conversation_id: conversationId,
          revision: 1,
          events: [
            {
              event_id: 'e76aa730-c29a-45e0-84fc-c9b88d819e69',
              revision: 1,
              kind: 'user_text',
              content: 'synthetic first note',
              correlation_id: '0ee18285-c27e-4fbe-80d2-f46ec34c311c',
            },
          ],
          generation_jobs: [
            {
              job_id: 'f4398089-4927-4ccb-a27d-11736920f697',
              source_outbox_id: 'a1d92084-e0a8-4582-81b9-b3e6f38173a0',
              conversation_id: conversationId,
              source_event_id: 'e76aa730-c29a-45e0-84fc-c9b88d819e69',
              kind: 'conversation_response_v1',
              state: 'queued',
              revision: 1,
              attempts_started: 0,
              max_attempts: 3,
              queue_wait_micros: '0',
              execution_micros: '0',
              failure_kind: null,
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          conversations: [{ conversation_id: conversationId, revision: 1 }],
        }),
      )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('crypto', {
      randomUUID: vi
        .fn()
        .mockReturnValueOnce(conversationId)
        .mockReturnValueOnce('a1b06fd4-39a2-4210-940c-ace9d47a610b'),
    })
    const user = userEvent.setup()

    await renderFreshApp()
    await user.click(await screen.findByRole('button', { name: '새 기록' }))
    await user.type(
      screen.getByLabelText('기록할 내용'),
      'synthetic first note',
    )

    expect(
      within(screen.getByRole('log')).queryByText('synthetic first note'),
    ).toBeNull()
    await user.click(screen.getByRole('button', { name: '기록하기' }))

    expect(await screen.findByText('synthetic first note')).toBeTruthy()
    expect(
      screen.getByText('기록은 저장됐고 로컬 응답을 기다리고 있습니다.'),
    ).toBeTruthy()
    const appendCalls = fetchMock.mock.calls.filter(([path]) =>
      String(path).endsWith(`/conversations/${conversationId}/events`),
    )
    expect(appendCalls).toHaveLength(2)
    expect(appendCalls[0]?.[1]?.body).toBe(appendCalls[1]?.[1]?.body)
    const body = JSON.parse(String(appendCalls[0]?.[1]?.body)) as Record<
      string,
      unknown
    >
    expect(body).toEqual({
      idempotency_key: 'a1b06fd4-39a2-4210-940c-ace9d47a610b',
      content: 'synthetic first note',
    })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(6))
    expect(jsdom.window.localStorage).toHaveLength(0)
    expect(jsdom.window.sessionStorage).toHaveLength(0)
  })

  it('keeps one cancellation key across access refresh and shows the durable state', async () => {
    const conversationId = '47c0d72f-8cc0-4a57-8232-8b38547ca710'
    const eventId = 'e76aa730-c29a-45e0-84fc-c9b88d819e69'
    const jobId = 'f4398089-4927-4ccb-a27d-11736920f697'
    const cancelKey = 'bf859d55-4c9c-48db-a557-2b748c707b81'
    const queuedJob = {
      job_id: jobId,
      source_outbox_id: 'a1d92084-e0a8-4582-81b9-b3e6f38173a0',
      conversation_id: conversationId,
      source_event_id: eventId,
      kind: 'conversation_response_v1',
      state: 'queued',
      revision: 1,
      attempts_started: 0,
      max_attempts: 3,
      queue_wait_micros: '0',
      execution_micros: '0',
      failure_kind: null,
    }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          access_token: 'synthetic-access-token',
          token_type: 'Bearer',
          expires_at: 4_102_444_800,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          conversations: [{ conversation_id: conversationId, revision: 1 }],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          conversation_id: conversationId,
          revision: 1,
          events: [
            {
              event_id: eventId,
              revision: 1,
              kind: 'user_text',
              content: 'cancel this local response',
              correlation_id: '0ee18285-c27e-4fbe-80d2-f46ec34c311c',
            },
          ],
          generation_jobs: [queuedJob],
        }),
      )
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid_token' }))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          access_token: 'rotated-synthetic-access-token',
          token_type: 'Bearer',
          expires_at: 4_102_444_900,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          job: { ...queuedJob, state: 'cancel_requested', revision: 2 },
          replayed: false,
        }),
      )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('crypto', { randomUUID: vi.fn().mockReturnValue(cancelKey) })
    const user = userEvent.setup()

    await renderFreshApp()
    await user.click(
      await screen.findByRole('button', { name: /기록 47c0d72f/ }),
    )
    await user.click(await screen.findByRole('button', { name: '응답 취소' }))

    expect(
      await screen.findByText('로컬 응답을 취소하고 있습니다.'),
    ).toBeTruthy()
    const cancelCalls = fetchMock.mock.calls.filter(([path]) =>
      String(path).endsWith(`/jobs/${jobId}/cancel`),
    )
    expect(cancelCalls).toHaveLength(2)
    expect(cancelCalls[0]?.[1]?.body).toBe(cancelCalls[1]?.[1]?.body)
    expect(JSON.parse(String(cancelCalls[0]?.[1]?.body))).toEqual({
      idempotency_key: cancelKey,
      expected_revision: 1,
    })
  })

  it('distinguishes unavailable, timeout, crash, cancellation, and recovery states', async () => {
    const conversationId = '47c0d72f-8cc0-4a57-8232-8b38547ca710'
    const failures = [
      ['provider_unavailable', 'failed'],
      ['timeout', 'retry_scheduled'],
      ['execution_failed', 'failed'],
      [null, 'cancelled'],
      ['cleanup_uncertain', 'recovery_required'],
    ] as const
    const events = failures.map((_, index) => ({
      event_id: `0000000${index + 1}-0000-4000-8000-00000000000${index + 1}`,
      revision: index + 1,
      kind: 'user_text',
      content: `source ${index + 1}`,
      correlation_id: `1000000${index + 1}-0000-4000-8000-00000000000${index + 1}`,
    }))
    const generationJobs = failures.map(([failure, state], index) => ({
      job_id: `2000000${index + 1}-0000-4000-8000-00000000000${index + 1}`,
      source_outbox_id: `3000000${index + 1}-0000-4000-8000-00000000000${index + 1}`,
      conversation_id: conversationId,
      source_event_id: events[index].event_id,
      kind: 'conversation_response_v1',
      state,
      revision: 2,
      attempts_started: 1,
      max_attempts: 3,
      queue_wait_micros: '1',
      execution_micros: '2',
      failure_kind: failure,
    }))
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          access_token: 'synthetic-access-token',
          token_type: 'Bearer',
          expires_at: 4_102_444_800,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          conversations: [{ conversation_id: conversationId, revision: 5 }],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          conversation_id: conversationId,
          revision: 5,
          events,
          generation_jobs: generationJobs,
        }),
      )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    await renderFreshApp()
    await user.click(
      await screen.findByRole('button', { name: /기록 47c0d72f/ }),
    )

    for (const message of [
      '로컬 모델을 사용할 수 없어 응답을 만들지 못했습니다.',
      '응답 시간이 초과되어 다시 시도합니다.',
      '로컬 provider가 중단되어 응답을 만들지 못했습니다.',
      '로컬 응답 생성을 취소했습니다.',
      'provider 종료를 확인해야 합니다. 생성 queue를 중단했습니다.',
    ]) {
      expect(await screen.findByText(message)).toBeTruthy()
    }
  })

  it('does not claim server logout when refresh-session revocation is unconfirmed', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          access_token: 'synthetic-access-token',
          token_type: 'Bearer',
          expires_at: 4_102_444_800,
        }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { conversations: [] }))
      .mockResolvedValueOnce(
        jsonResponse(503, { error: 'authentication_unavailable' }),
      )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    await renderFreshApp()
    await user.click(await screen.findByRole('button', { name: '로그아웃' }))

    expect(
      await screen.findByText(
        '이 화면의 액세스만 종료했습니다. 서버 세션 상태는 미확인입니다.',
      ),
    ).toBeTruthy()
    expect(
      screen.getByText(/서버 세션 폐기를 확인하지 못했습니다/),
    ).toBeTruthy()
    expect(jsdom.window.localStorage).toHaveLength(0)
    expect(jsdom.window.sessionStorage).toHaveLength(0)
  })
})
