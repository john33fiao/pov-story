#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(dirname "$script_dir")
base_url="http://127.0.0.1:8080"
cargo_command=${CARGO:-cargo}
instance_root=${POV_INSTANCE_ROOT:-}

if [ -z "$instance_root" ]; then
  echo "POV_INSTANCE_ROOT must name an instance completed by production auth init." >&2
  exit 1
fi

cd "$repository_root"

if curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
  "$base_url/api/health" >/dev/null 2>&1; then
  echo "Port 8080 is already serving an HTTP health response." >&2
  exit 1
fi

"$cargo_command" build --locked --release -p pov-api
./target/release/pov-api --instance-root "$instance_root" &
server_pid=$!

cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

attempt=0
while [ "$attempt" -lt 40 ]; do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "POV Story server exited before becoming ready." >&2
    exit 1
  fi

  if curl --connect-timeout 2 --max-time 5 --fail --silent \
    "$base_url/api/health" >/dev/null 2>&1; then
    break
  fi

  attempt=$((attempt + 1))
  sleep 0.25
done

health_body=$(
  curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
    "$base_url/api/health"
)
shell_body=$(
  curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
    "$base_url/"
)
missing_api_status=$(
  curl --connect-timeout 2 --max-time 5 --silent --output /dev/null \
    --write-out "%{http_code}" \
    "$base_url/api/missing"
)

case "$health_body" in
  '{"status":"ok"}') ;;
  *)
    echo "Unexpected health response: $health_body" >&2
    exit 1
    ;;
esac

case "$shell_body" in
  *'<div id="root"></div>'*) ;;
  *)
    echo "Frontend shell marker was not served." >&2
    exit 1
    ;;
esac

case "$shell_body" in
  *'http://'* | *'https://'*)
    echo "Frontend shell contains an external URL." >&2
    exit 1
    ;;
esac

if [ "$missing_api_status" != "404" ]; then
  echo "Unknown API path returned $missing_api_status instead of 404." >&2
  exit 1
fi

echo "Smoke passed: frontend shell and health API share $base_url"
