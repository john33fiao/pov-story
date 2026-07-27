const capabilities = [
  ['Origin', '127.0.0.1:8080'],
  ['Network', 'Internet not required'],
  ['Source', 'App-owned data only'],
] as const

export default function App() {
  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="POV Story 홈">
          <span className="brand-mark" aria-hidden="true">
            P
          </span>
          <span>POV Story</span>
        </a>
        <p className="local-status">
          <span className="status-dot" aria-hidden="true" />
          Local shell ready
        </p>
      </header>

      <section className="hero" aria-labelledby="hero-title">
        <p className="eyebrow">LOCAL-FIRST LIFELOG</p>
        <h1 id="hero-title">
          기록은 이 장치에,
          <br />
          맥락은 다시 찾을 수 있게.
        </h1>
        <p className="intro">
          POV Story의 첫 실행 경계입니다. 지금은 인터넷이나 외부 앱 없이 열리는
          Web Chat 기반을 검증하고 있습니다.
        </p>

        <dl className="capabilities">
          {capabilities.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <footer>
        <code>GET /api/health</code>
        <span>Walking skeleton · H0</span>
      </footer>
    </main>
  )
}
