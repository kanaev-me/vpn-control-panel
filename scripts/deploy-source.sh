#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE=""

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/deploy-source.sh --env PATH

Deploy materialized panel sources using an explicit tenant configuration.
The command requires an existing hwdsl2 IKEv2 installation and never deploys
or replaces its database, certificates, profiles, keys or helper script.
EOF
}

while (($#)); do
  case "$1" in
    --env)
      [[ $# -ge 2 ]] || { echo "--env requires a path" >&2; exit 2; }
      ENV_FILE="$2"
      shift 2
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

[[ -n "$ENV_FILE" ]] || { echo "Explicit --env is required" >&2; exit 2; }
[[ -f "$ENV_FILE" ]] || { echo "Tenant env not found: $ENV_FILE" >&2; exit 2; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root" >&2; exit 2; }

STAGE="$(mktemp -d)"
cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

python3 "$ROOT/scripts/render-tenant-deployment.py" \
  --env "$ENV_FILE" \
  --output "$STAGE/rendered"

# Resolve only the paths and service names required for a source-only deploy.
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
    "APP_DIR": str(config.app_dir),
    "PANEL_SERVICE": config.panel_service,
    "IKEV2_SCRIPT": str(config.ikev2_script),
    "CERT_DB": config.cert_db,
    "IPSEC_SERVICE": config.ipsec_service,
    "PUBLIC_DOMAIN": config.public_domain,
    "PANEL_HOST": config.panel_host,
    "PANEL_PORT": str(config.panel_port),
    "SERVICE_PREFIX": config.service_prefix,
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

python3 "$ROOT/scripts/materialize-tenant-panel.py" \
  --output "$STAGE/panel" \
  --service-prefix "$SERVICE_PREFIX"

STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_ROOT="$APP_DIR/.deploy-backups"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
install -d -m 0755 "$APP_DIR"
install -d -m 0700 "$BACKUP_ROOT" "$BACKUP_DIR"

for path in "$APP_DIR"/*.py "$APP_DIR"/*.sh "$APP_DIR/panel.env"; do
  [[ -e "$path" ]] || continue
  cp -a "$path" "$BACKUP_DIR/"
done

install -m 0755 "$STAGE/panel/"*.py "$APP_DIR/"
install -m 0755 "$STAGE/panel/"*.sh "$APP_DIR/" 2>/dev/null || true
install -m 0600 "$STAGE/rendered/panel.env" "$APP_DIR/panel.env"

python3 -m compileall -q "$APP_DIR"
systemctl restart "$PANEL_SERVICE"

HEALTH_HOST="$PANEL_HOST"
case "$HEALTH_HOST" in
  0.0.0.0|::|'[::]') HEALTH_HOST=127.0.0.1 ;;
esac
curl -fsS "http://${HEALTH_HOST}:${PANEL_PORT}/health" >/dev/null

printf 'deploy OK; app_dir=%s; service=%s; backup=%s; vpn_prerequisites=verified\n' \
  "$APP_DIR" "$PANEL_SERVICE" "$BACKUP_DIR"
