import { expect, test } from '@playwright/test'

type RecordedRequest = {
  url: string
  authorization: string | null
  lastEventId: string | null
  credentials: RequestCredentials | null
  cache: RequestCache | null
}

test('resumes across refresh and reload without persisting bearer tokens', async ({
  page,
}) => {
  const requests: RecordedRequest[] = []
  await page.exposeFunction(
    '__recordJobRequest',
    (request: RecordedRequest) => {
      requests.push(request)
    },
  )
  await page.addInitScript(() => {
    const primaryToken = 'token-canary-primary'
    const rotatedToken = 'token-canary-rotated'
    const encoder = new TextEncoder()
    const realFetch = window.fetch.bind(window)
    let refreshCount = 0

    function json(value: unknown, status = 200) {
      return new Response(JSON.stringify(value), {
        status,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    function statusEvent(cursor: string) {
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

    window.fetch = async (input, init) => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url
      if (url === '/api/auth/refresh') {
        refreshCount += 1
        return json({
          access_token: refreshCount === 1 ? primaryToken : rotatedToken,
          token_type: 'Bearer',
          expires_at:
            refreshCount === 1
              ? Math.floor(Date.now() / 1000) + 6
              : Math.floor(Date.now() / 1000) + 3600,
        })
      }
      if (url === '/api/conversations') {
        return json({ conversations: [] })
      }
      if (url === '/api/jobs/events/stream') {
        const headers = new Headers(init?.headers)
        const lastEventId = headers.get('Last-Event-ID')
        await (
          window as typeof window & {
            __recordJobRequest: (request: RecordedRequest) => Promise<void>
          }
        ).__recordJobRequest({
          url,
          authorization: headers.get('Authorization'),
          lastEventId,
          credentials: init?.credentials ?? null,
          cache: init?.cache ?? null,
        })
        const cursor =
          lastEventId === null ? '17' : (BigInt(lastEventId) + 1n).toString()
        const payload = statusEvent(cursor)
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(
              encoder.encode(
                `event: job_status\nid: ${cursor}\ndata: ${JSON.stringify(payload)}\n\n`,
              ),
            )
          },
        })
        return new Response(body, {
          status: 200,
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-store',
          },
        })
      }
      return realFetch(input, init)
    }
  })

  await page.goto('/')
  await expect(page.getByText('실시간 상태 연결됨')).toBeVisible()
  await expect
    .poll(() => requests.some((request) => request.lastEventId === '17'))
    .toBe(true)
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.sessionStorage.getItem('pov.job-events.cursor.v1'),
      ),
    )
    .toBe('18')

  const refreshHandoff = requests.find(
    (request) => request.lastEventId === '17',
  )
  expect(refreshHandoff).toMatchObject({
    url: '/api/jobs/events/stream',
    authorization: 'Bearer token-canary-rotated',
    credentials: 'omit',
    cache: 'no-store',
  })
  expect(refreshHandoff?.url).not.toContain('token-canary')

  await page.reload()
  await expect
    .poll(() => requests.some((request) => request.lastEventId === '18'))
    .toBe(true)
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.sessionStorage.getItem('pov.job-events.cursor.v1'),
      ),
    )
    .toBe('19')

  const persisted = await page.evaluate(async () => {
    const local = Object.values(window.localStorage)
    const session = Object.values(window.sessionStorage)
    const cacheValues: string[] = []
    for (const name of await caches.keys()) {
      const cache = await caches.open(name)
      for (const request of await cache.keys()) {
        cacheValues.push(request.url)
        const response = await cache.match(request)
        if (response) cacheValues.push(await response.clone().text())
      }
    }
    return { local, session, cacheValues }
  })
  expect(JSON.stringify(persisted)).not.toContain('token-canary-primary')
  expect(JSON.stringify(persisted)).not.toContain('token-canary-rotated')
})
