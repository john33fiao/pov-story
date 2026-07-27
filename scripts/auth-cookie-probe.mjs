import http from "node:http";

const primaryPort = 18080;
const secondaryPort = 18081;
const listenHost = "127.0.0.1";
const probeHost = "localhost";
const probeCookieName = "pov_cookie_probe_local";
const productionCookieNames = ["pov_refresh_local", "__Host-pov_refresh"];
const canary = "synthetic-pov005-refresh";
const localProductionSpecimen =
  "pov_refresh_local=<opaque>; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=604800";
const remoteProductionSpecimen =
  "__Host-pov_refresh=<opaque>; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200";

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function html(title, detail, links = []) {
  const navigation = links
    .map(
      ({ href, label }) =>
        `<li><a href="${escapeHtml(href)}">${escapeHtml(label)}</a></li>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(title)}</h1>
      <p id="result">${escapeHtml(detail)}</p>
      <ul>${navigation}</ul>
    </main>
  </body>
</html>`;
}

function send(response, status, body, headers = {}) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "text/html; charset=utf-8",
    ...headers,
  });
  response.end(body);
}

function rejectUnsafeRequest(request, response, expectedHost) {
  if (request.headers.host !== expectedHost) {
    send(
      response,
      421,
      html("Unexpected Host refused", "Open the exact localhost probe URL."),
    );
    return true;
  }

  const names = new Set(
    (request.headers.cookie ?? "")
      .split(";")
      .map((part) => part.trim().split("=", 1)[0]),
  );
  if (!productionCookieNames.some((name) => names.has(name))) {
    return false;
  }

  send(
    response,
    409,
    html(
      "Production cookie refused",
      "Use a disposable browser state for this probe host.",
    ),
  );
  return true;
}

function probeCookie(maxAge) {
  return [
    `${probeCookieName}=${maxAge === 0 ? "" : canary}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/api/auth",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

function primaryHandler(request, response) {
  if (
    rejectUnsafeRequest(request, response, `${probeHost}:${primaryPort}`)
  ) {
    return;
  }

  if (request.url === "/") {
    send(
      response,
      200,
      html("POV-005 cookie probe", "Synthetic data only.", [
        { href: "/probe/local/set", label: "Set local profile cookie" },
        { href: "/probe/local/header", label: "Inspect local profile specimen" },
        { href: "/api/auth/echo", label: "Check primary port" },
        {
          href: `http://${probeHost}:${secondaryPort}/api/auth/echo`,
          label: "Check secondary port",
        },
        { href: "/probe/user-agent", label: "Record browser user agent" },
        { href: "/probe/local/clear", label: "Clear synthetic cookie" },
        {
          href: "/probe/remote/header",
          label: "Inspect remote profile header",
        },
      ]),
    );
    return;
  }

  if (request.url === "/probe/local/set") {
    send(
      response,
      200,
      html("Local cookie issued", "A synthetic HttpOnly cookie was issued.", [
        { href: "/api/auth/echo", label: "Check primary port" },
        {
          href: `http://${probeHost}:${secondaryPort}/api/auth/echo`,
          label: "Check secondary port",
        },
        { href: "/probe/user-agent", label: "Record browser user agent" },
        { href: "/probe/local/clear", label: "Clear synthetic cookie" },
      ]),
      { "Set-Cookie": probeCookie(600) },
    );
    return;
  }

  if (request.url === "/api/auth/echo") {
    const present = (request.headers.cookie ?? "").includes(
      `${probeCookieName}=${canary}`,
    );
    send(
      response,
      200,
      html("Primary port", `local-cookie-present=${present}`, [
        {
          href: `http://${probeHost}:${secondaryPort}/api/auth/echo`,
          label: "Check secondary port",
        },
        { href: "/probe/local/clear", label: "Clear synthetic cookie" },
      ]),
    );
    return;
  }

  if (request.url === "/probe/local/clear") {
    send(
      response,
      200,
      html("Synthetic cookie cleared", "The local probe cookie was expired."),
      { "Set-Cookie": probeCookie(0) },
    );
    return;
  }

  if (request.url === "/probe/user-agent") {
    send(
      response,
      200,
      html(
        "Browser user agent",
        request.headers["user-agent"] ?? "user-agent-missing",
      ),
    );
    return;
  }

  if (request.url === "/probe/local/header") {
    send(
      response,
      200,
      html(
        "Local header specimen",
        "No production-named cookie is issued by this endpoint.",
      ),
      { "X-POV-Set-Cookie-Specimen": localProductionSpecimen },
    );
    return;
  }

  if (request.url === "/probe/remote/header") {
    send(
      response,
      200,
      html(
        "Remote header specimen",
        "No production-named cookie is issued; this is not an HTTPS compatibility test.",
      ),
      { "X-POV-Set-Cookie-Specimen": remoteProductionSpecimen },
    );
    return;
  }

  send(response, 404, html("Not found", "Unknown probe path."));
}

function secondaryHandler(request, response) {
  if (
    rejectUnsafeRequest(request, response, `${probeHost}:${secondaryPort}`)
  ) {
    return;
  }

  if (request.url === "/api/auth/echo") {
    const present = (request.headers.cookie ?? "").includes(
      `${probeCookieName}=${canary}`,
    );
    send(
      response,
      200,
      html("Secondary port", `local-cookie-present=${present}`, [
        {
          href: `http://${probeHost}:${primaryPort}/probe/local/clear`,
          label: "Clear synthetic cookie",
        },
      ]),
    );
    return;
  }

  send(response, 404, html("Not found", "Unknown probe path."));
}

const primary = http.createServer(primaryHandler);
const secondary = http.createServer(secondaryHandler);

await Promise.all([
  new Promise((resolve) =>
    primary.listen(primaryPort, listenHost, resolve),
  ),
  new Promise((resolve) =>
    secondary.listen(secondaryPort, listenHost, resolve),
  ),
]);

console.log(
  [
    "POV-005 synthetic cookie probe is ready:",
    `  open http://${probeHost}:${primaryPort}/`,
    `  compare production specimens with curl -D - http://${probeHost}:${primaryPort}/probe/local/header`,
    `  and curl -D - http://${probeHost}:${primaryPort}/probe/remote/header`,
    `  listener is ${listenHost}; exact navigation Host is ${probeHost}`,
    `  browser state uses probe-only cookie ${probeCookieName}`,
    "Press Ctrl-C when finished.",
  ].join("\n"),
);

function close() {
  primary.close();
  secondary.close();
}

process.on("SIGINT", close);
process.on("SIGTERM", close);
