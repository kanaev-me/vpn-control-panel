#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")" && pwd)"

parse_env_config() {
  local env_file="$1"
  python3 - "$ROOT" "$env_file" <<'PY'
from pathlib import Path
import shlex
import sys

root = Path(sys.argv[1])
env_path = Path(sys.argv[2])
sys.path.insert(0, str(root / "panel"))
from runtime_config import load_runtime_config


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        value = value.strip()
        if value and value[0] in {chr(39), chr(34)}:
            parsed = shlex.split(value)
            if len(parsed) != 1:
                raise ValueError(f"{path}:{line_number}: invalid quoted value")
            value = parsed[0]
        values[key.strip()] = value
    return values


config = load_runtime_config(parse_env(env_path))
for key, value in {
    "APP_NAME": config.app_name,
    "DB_PATH": str(config.db_path),
    "PANEL_SERVICE": config.panel_service,
    "CADDY_SERVICE": config.caddy_service,
    "IPSEC_SERVICE": config.ipsec_service,
    "PANEL_HOST": config.panel_host,
    "PANEL_PORT": str(config.panel_port),
    "DEFAULT_GROUP": config.default_access_group,
}.items():
    print(f"{key}={shlex.quote(value)}")
PY
}

health_host() {
  case "$1" in
    0.0.0.0|::|'[::]') printf '127.0.0.1\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

verify_installed_login() {
  local host="$1" port="$2" username="$3" password_file="$4" app_name="$5"
  python3 - "$host" "$port" "$username" "$password_file" "$app_name" <<'PY'
import http.client
import json
from pathlib import Path
import sys
from urllib.parse import urlencode

host, port_text, username, password_path, app_name = sys.argv[1:]
port = int(port_text)
password = Path(password_path).read_text(encoding="utf-8").rstrip("\r\n")


def request(method: str, path: str, *, body: bytes | None = None, cookie: str = ""):
    connection = http.client.HTTPConnection(host, port, timeout=20)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    if cookie:
        headers["Cookie"] = cookie
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        return response.status, response.getheaders(), payload
    finally:
        connection.close()


login_body = urlencode({"username": username, "password": password}).encode("utf-8")
status, headers, _body = request("POST", "/login", body=login_body)
header_map = {key.casefold(): value for key, value in headers}
if status != 303 or header_map.get("location") != "/":
    raise RuntimeError(f"administrator login failed: HTTP {status}")

set_cookie = header_map.get("set-cookie", "")
cookie = set_cookie.split(";", 1)[0].strip()
if not cookie.startswith("vpn_vpn_session=") or len(cookie.split("=", 1)[1]) < 32:
    raise RuntimeError("administrator login did not return a valid secure session cookie")

status, _headers, payload = request("GET", "/", cookie=cookie)
home = payload.decode("utf-8", "replace")
if status != 200 or app_name not in home or 'href="/access"' not in home:
    raise RuntimeError("administrator login did not open the protected home page")
for forbidden in ("panel unknown", "caddy unknown", "ipsec unknown"):
    if forbidden in home:
        raise RuntimeError(f"protected home contains invalid service state: {forbidden}")

for path, marker in (("/access", "Доступ"), ("/channel", "Канал")):
    status, _headers, payload = request("GET", path, cookie=cookie)
    body = payload.decode("utf-8", "replace")
    if status != 200 or marker not in body:
        raise RuntimeError(f"protected page verification failed: {path}")

status, _headers, payload = request("GET", "/api/me", cookie=cookie)
identity = json.loads(payload.decode("utf-8"))
if status != 200 or identity.get("username") != username:
    raise RuntimeError("authenticated identity verification failed")

print("administrator_login=ok")
print("protected_pages=ok")
print("dashboard_defaults=ok")
PY
}

prompt_password_file() {
  local output_file="$1"
  local password_one password_two
  while true; do
    read -r -s -p "Initial panel administrator password: " password_one
    echo
    read -r -s -p "Repeat panel administrator password: " password_two
    echo
    if [[ "$password_one" != "$password_two" ]]; then
      echo "Passwords do not match. Try again." >&2
      continue
    fi
    if [[ ${#password_one} -lt 12 ]]; then
      echo "Password must contain at least 12 characters. Try again." >&2
      continue
    fi
    break
  done
  printf '%s\n' "$password_one" > "$output_file"
  unset password_one password_two
}

reset_admin_password() {
  local env_file=""
  local admin_user="admin"
  local admin_display_name="Administrator"

  while (($#)); do
    case "$1" in
      --env)
        [[ $# -ge 2 ]] || { echo "--env requires a path" >&2; exit 2; }
        env_file="$2"
        shift 2
        ;;
      --admin-user)
        [[ $# -ge 2 ]] || { echo "--admin-user requires a value" >&2; exit 2; }
        admin_user="$2"
        shift 2
        ;;
      --admin-display-name)
        [[ $# -ge 2 ]] || { echo "--admin-display-name requires a value" >&2; exit 2; }
        admin_display_name="$2"
        shift 2
        ;;
      -h|--help)
        cat <<'EOF'
Usage:
  sudo ./install.sh reset-admin-password --env PATH [options]

Options:
  --admin-user NAME
  --admin-display-name NAME
EOF
        return 0
        ;;
      *)
        echo "Unknown reset argument: $1" >&2
        exit 2
        ;;
    esac
  done

  [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root" >&2; exit 2; }
  [[ -n "$env_file" ]] || { echo "Explicit --env is required" >&2; exit 2; }
  [[ -f "$env_file" ]] || { echo "Tenant env not found: $env_file" >&2; exit 2; }

  eval "$(parse_env_config "$env_file")"
  [[ -f "$DB_PATH" ]] || { echo "Panel database not found: $DB_PATH" >&2; exit 2; }

  local stage backup service_stopped=0 host
  stage="$(mktemp -d)"
  cleanup_reset() {
    rm -rf "$stage"
    if [[ $service_stopped -eq 1 ]]; then
      systemctl start "$PANEL_SERVICE" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_reset EXIT

  prompt_password_file "$stage/admin.password"
  backup="${DB_PATH}.before-password-reset-$(date +%Y%m%d_%H%M%S)"
  cp -a "$DB_PATH" "$backup"

  systemctl stop "$PANEL_SERVICE"
  service_stopped=1

  python3 "$ROOT/scripts/bootstrap-panel-admin.py" \
    --db "$DB_PATH" \
    --username "$admin_user" \
    --display-name "$admin_display_name" \
    --password-file "$stage/admin.password" \
    --default-group "$DEFAULT_GROUP" \
    --replace-existing

  python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
try:
    conn.execute("DELETE FROM panel_sessions")
    conn.commit()
    result = conn.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError(f"SQLite integrity check failed: {result!r}")
finally:
    conn.close()
PY

  systemctl start "$PANEL_SERVICE"
  service_stopped=0
  host="$(health_host "$PANEL_HOST")"
  for _attempt in $(seq 1 30); do
    if curl -fsS "http://${host}:${PANEL_PORT}/health" >/dev/null; then
      break
    fi
    sleep 1
  done
  curl -fsS "http://${host}:${PANEL_PORT}/health" >/dev/null
  verify_installed_login "$host" "$PANEL_PORT" "$admin_user" "$stage/admin.password" "$APP_NAME"

  printf '\nAdministrator password reset completed.\n'
  printf 'Administrator: %s\n' "$admin_user"
  printf 'Backup: %s\n' "$backup"
}

if [[ ${1:-} == "reset-admin-password" ]]; then
  shift
  reset_admin_password "$@"
  exit 0
fi

ENV_FILE=""
ADMIN_USER="admin"
ADMIN_PASSWORD_FILE=""
SKIP_CADDY=0
for ((index = 1; index <= $#; index++)); do
  argument="${!index}"
  if [[ "$argument" == "--env" && $index -lt $# ]]; then
    next_index=$((index + 1))
    ENV_FILE="${!next_index}"
  elif [[ "$argument" == "--admin-user" && $index -lt $# ]]; then
    next_index=$((index + 1))
    ADMIN_USER="${!next_index}"
  elif [[ "$argument" == "--admin-password-file" && $index -lt $# ]]; then
    next_index=$((index + 1))
    ADMIN_PASSWORD_FILE="${!next_index}"
  elif [[ "$argument" == "--skip-caddy" ]]; then
    SKIP_CADDY=1
  fi
done

[[ -n "$ENV_FILE" ]] || exec "$ROOT/scripts/install-clean-server.sh" "$@"
[[ -f "$ENV_FILE" ]] || exec "$ROOT/scripts/install-clean-server.sh" "$@"
eval "$(parse_env_config "$ENV_FILE")"

# This is the clean-install entrypoint. Refuse before any server changes when a
# panel database already exists; existing installations must use deploy-source.
if [[ -e "$DB_PATH" ]]; then
  printf 'Panel database already exists: %s\n' "$DB_PATH" >&2
  printf 'Clean installation refused. Use scripts/deploy-source.sh to update an existing panel.\n' >&2
  exit 2
fi

STAGE="$(mktemp -d)"
cleanup_install() {
  rm -rf "$STAGE"
}
trap cleanup_install EXIT

if [[ -z "$ADMIN_PASSWORD_FILE" ]]; then
  [[ -t 0 ]] || {
    echo "--admin-password-file is required for a non-interactive install" >&2
    exit 2
  }
  prompt_password_file "$STAGE/admin.password"
  ADMIN_PASSWORD_FILE="$STAGE/admin.password"
  set -- "$@" --admin-password-file "$ADMIN_PASSWORD_FILE"
else
  [[ -f "$ADMIN_PASSWORD_FILE" ]] || {
    echo "Administrator password file not found: $ADMIN_PASSWORD_FILE" >&2
    exit 2
  }
fi

"$ROOT/scripts/install-clean-server.sh" "$@"

HOST="$(health_host "$PANEL_HOST")"
systemctl is-active --quiet "$PANEL_SERVICE"
systemctl is-active --quiet "$IPSEC_SERVICE"
if [[ $SKIP_CADDY -eq 0 ]]; then
  systemctl is-active --quiet "$CADDY_SERVICE"
fi
verify_installed_login "$HOST" "$PANEL_PORT" "$ADMIN_USER" "$ADMIN_PASSWORD_FILE" "$APP_NAME"

printf '\nPublic installation verification completed.\n'
printf 'Administrator login: verified\n'
printf 'Protected pages: verified\n'
printf 'Dashboard defaults: verified\n'
