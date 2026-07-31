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
