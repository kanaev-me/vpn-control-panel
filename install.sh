#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE=""

for ((index = 1; index <= $#; index++)); do
  argument="${!index}"
  if [[ "$argument" == "--env" && $index -lt $# ]]; then
    next_index=$((index + 1))
    ENV_FILE="${!next_index}"
    break
  fi
done

# This is the clean-install entrypoint. Refuse before any server changes when a
# panel database already exists; existing installations must use deploy-source.
if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]] && command -v python3 >/dev/null; then
  python3 - "$ROOT" "$ENV_FILE" <<'PY'
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
if config.db_path.exists():
    print(
        f"Panel database already exists: {config.db_path}\n"
        "Clean installation refused. Use scripts/deploy-source.sh to update "
        "an existing panel.",
        file=sys.stderr,
    )
    raise SystemExit(2)
PY
fi

exec "$ROOT/scripts/install-clean-server.sh" "$@"
