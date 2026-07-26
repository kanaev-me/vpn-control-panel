#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE=""
ADMIN_USER="admin"
ADMIN_DISPLAY_NAME="Administrator"
ADMIN_PASSWORD_FILE=""
SKIP_PACKAGES=0
SKIP_CADDY=0

usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh --env PATH [options]

Required prerequisite:
  Install hwdsl2/setup-ipsec-vpn with IKEv2 before running this command.
  The panel installer verifies the existing Libreswan service, IKEv2 helper,
  configuration and NSS certificate database before changing the server.

Required:
  --env PATH                    Tenant environment file

Administrator:
  --admin-user NAME             Initial owner username (default: admin)
  --admin-display-name NAME     Display name (default: Administrator)
  --admin-password-file PATH    File containing the initial password

Optional:
  --skip-packages               Do not run apt-get
  --skip-caddy                  Do not install or configure Caddy
  -h, --help                    Show this help

When --admin-password-file is omitted in a terminal, the installer asks for the
password without echoing it. The installer never installs or replaces the VPN
stack, IKEv2 helper, database, profile, certificate or secret from Git.
EOF
}

while (($#)); do
  case "$1" in
    --env)
      [[ $# -ge 2 ]] || { echo "--env requires a path" >&2; exit 2; }
      ENV_FILE="$2"
      shift 2
      ;;
    --admin-user)
      [[ $# -ge 2 ]] || { echo "--admin-user requires a value" >&2; exit 2; }
      ADMIN_USER="$2"
      shift 2
      ;;
    --admin-display-name)
      [[ $# -ge 2 ]] || { echo "--admin-display-name requires a value" >&2; exit 2; }
      ADMIN_DISPLAY_NAME="$2"
      shift 2
      ;;
    --admin-password-file)
      [[ $# -ge 2 ]] || { echo "--admin-password-file requires a path" >&2; exit 2; }
      ADMIN_PASSWORD_FILE="$2"
      shift 2
      ;;
    --skip-packages)
      SKIP_PACKAGES=1
      shift
      ;;
    --skip-caddy)
      SKIP_CADDY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root" >&2; exit 2; }
[[ -n "$ENV_FILE" ]] || { echo "Explicit --env is required" >&2; exit 2; }
[[ -f "$ENV_FILE" ]] || { echo "Tenant env not found: $ENV_FILE" >&2; exit 2; }
command -v python3 >/dev/null || {
  echo "Python 3 is required to validate the tenant configuration" >&2
  exit 2
}

STAGE="$(mktemp -d)"
cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

# Resolve and validate the tenant before asking for a password or installing
# anything. This keeps a missing VPN prerequisite completely non-destructive.
python3 "$ROOT/scripts/render-tenant-deployment.py" \
  --env "$ENV_FILE" \
  --output "$STAGE/rendered"

eval "$(python3 - "$ROOT" "$ENV_FILE" <<'PY'
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
resolved = {
    "APP_NAME": config.app_name,
    "PUBLIC_DOMAIN": config.public_domain,
    "SERVICE_PREFIX": config.service_prefix,
    "APP_DIR": str(config.app_dir),
    "DB_PATH": str(config.db_path),
    "ACTION_LOG": str(config.action_log),
    "STATUS_DIR": str(config.status_dir),
    "INSTRUCTIONS_DIR": str(config.instructions_dir),
    "CACHE_DIR": str(config.cache_dir),
    "IKEV2_SCRIPT": str(config.ikev2_script),
    "CERT_DB": config.cert_db,
    "PANEL_SERVICE": config.panel_service,
    "IPSEC_SERVICE": config.ipsec_service,
    "PANEL_HOST": config.panel_host,
    "PANEL_PORT": str(config.panel_port),
    "DEFAULT_GROUP": config.default_access_group,
}
for key, value in resolved.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

python3 "$ROOT/scripts/check-vpn-prerequisites.py" \
  --ikev2-script "$IKEV2_SCRIPT" \
  --cert-db "$CERT_DB" \
  --ipsec-service "$IPSEC_SERVICE" \
  --domain "$PUBLIC_DOMAIN"

if [[ -z "$ADMIN_PASSWORD_FILE" ]]; then
  [[ -t 0 ]] || {
    echo "--admin-password-file is required for a non-interactive install" >&2
    exit 2
  }
  read -r -s -p "Initial panel administrator password: " ADMIN_PASSWORD
  echo
  printf '%s\n' "$ADMIN_PASSWORD" > "$STAGE/admin.password"
  unset ADMIN_PASSWORD
  ADMIN_PASSWORD_FILE="$STAGE/admin.password"
fi
[[ -f "$ADMIN_PASSWORD_FILE" ]] || {
  echo "Administrator password file not found: $ADMIN_PASSWORD_FILE" >&2
  exit 2
}

if [[ $SKIP_PACKAGES -eq 0 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 sqlite3 curl libnss3-tools openssl
  if [[ $SKIP_CADDY -eq 0 ]]; then
    apt-get install -y caddy
  fi
fi

for command in python3 curl systemctl install; do
  command -v "$command" >/dev/null || {
    echo "Required command is missing: $command" >&2
    exit 2
  }
done

python3 "$ROOT/scripts/materialize-tenant-panel.py" \
  --output "$STAGE/panel" \
  --service-prefix "$SERVICE_PREFIX"

STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$APP_DIR/.install-backups/$STAMP"
if [[ -e "$APP_DIR/app.py" || -e "$APP_DIR/panel.env" || -e "$DB_PATH" ]]; then
  install -d -m 0700 "$BACKUP_DIR"
  for path in "$APP_DIR"/*.py "$APP_DIR"/*.sh "$APP_DIR/panel.env" "$DB_PATH"; do
    [[ -e "$path" ]] || continue
    cp -a "$path" "$BACKUP_DIR/"
  done
fi

install -d -m 0755 "$APP_DIR" "$STATUS_DIR" "$INSTRUCTIONS_DIR" "$CACHE_DIR"
install -d -m 0755 "$(dirname "$ACTION_LOG")" "$(dirname "$DB_PATH")"
install -m 0755 "$STAGE/panel/"*.py "$APP_DIR/"
install -m 0755 "$STAGE/panel/"*.sh "$APP_DIR/" 2>/dev/null || true
install -m 0600 "$STAGE/rendered/panel.env" "$APP_DIR/panel.env"

# The upstream helper and its CA/NSS state belong to hwdsl2. Never overwrite
# them from this repository; the preflight above proved they are already usable.
touch "$ACTION_LOG"
chmod 0600 "$ACTION_LOG"

python3 "$ROOT/scripts/bootstrap-panel-admin.py" \
  --db "$DB_PATH" \
  --username "$ADMIN_USER" \
  --display-name "$ADMIN_DISPLAY_NAME" \
  --password-file "$ADMIN_PASSWORD_FILE" \
  --default-group "$DEFAULT_GROUP"

python3 -m compileall -q "$APP_DIR"

for unit in "$STAGE/rendered/systemd/"*.service "$STAGE/rendered/systemd/"*.timer; do
  [[ -f "$unit" ]] || continue
  install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done

systemctl daemon-reload
systemctl enable --now "$PANEL_SERVICE"
while IFS= read -r timer; do
  [[ -n "$timer" ]] || continue
  systemctl enable --now "$timer"
done < "$STAGE/rendered/ENABLE.txt"

if [[ $SKIP_CADDY -eq 0 ]]; then
  command -v caddy >/dev/null || {
    echo "Caddy is missing; install it or use --skip-caddy" >&2
    exit 2
  }
  install -d -m 0755 /etc/caddy/conf.d
  install -m 0644 "$STAGE/rendered/Caddyfile" "/etc/caddy/conf.d/${SERVICE_PREFIX}.caddy"
  touch /etc/caddy/Caddyfile
  if ! grep -Fqx 'import /etc/caddy/conf.d/*.caddy' /etc/caddy/Caddyfile; then
    printf '\nimport /etc/caddy/conf.d/*.caddy\n' >> /etc/caddy/Caddyfile
  fi
  caddy validate --config /etc/caddy/Caddyfile
  systemctl enable caddy
  systemctl reload caddy 2>/dev/null || systemctl restart caddy
fi

HEALTH_HOST="$PANEL_HOST"
case "$HEALTH_HOST" in
  0.0.0.0|::|'[::]') HEALTH_HOST=127.0.0.1 ;;
esac

for _attempt in $(seq 1 30); do
  if curl -fsS "http://${HEALTH_HOST}:${PANEL_PORT}/health" >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS "http://${HEALTH_HOST}:${PANEL_PORT}/health" >/dev/null


printf '\nPanel installation completed.\n'
printf 'Application: %s\n' "$APP_NAME"
printf 'URL: https://%s\n' "$PUBLIC_DOMAIN"
printf 'Service: %s\n' "$PANEL_SERVICE"
printf 'Database: %s\n' "$DB_PATH"
printf 'Administrator: %s\n' "$ADMIN_USER"
printf 'VPN prerequisite: hwdsl2 IKEv2 verified\n'
if [[ -d "$BACKUP_DIR" ]]; then
  printf 'Backup: %s\n' "$BACKUP_DIR"
fi
