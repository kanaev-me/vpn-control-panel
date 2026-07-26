#!/usr/bin/env python3
"""Copy and validate the already tenant-neutral panel runtime."""

from __future__ import annotations

import argparse
import compileall
from pathlib import Path
import re
import shutil
import stat

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "panel"


def materialize(source: Path, output: Path, force: bool = False) -> None:
    if not source.is_dir():
        raise FileNotFoundError(f"panel source directory not found: {source}")
    if output.exists():
        if any(output.iterdir()) and not force:
            raise FileExistsError(f"output directory is not empty: {output}")
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    copied = 0
    for source_file in sorted(source.iterdir()):
        if not source_file.is_file() or source_file.suffix not in {".py", ".sh"}:
            continue
        target = output / source_file.name
        shutil.copy2(source_file, target)
        target.chmod(stat.S_IMODE(source_file.stat().st_mode))
        copied += 1

    if copied == 0:
        raise ValueError(f"no panel sources found in {source}")
    if not compileall.compile_dir(str(output), quiet=1, force=True):
        raise ValueError("panel sources do not compile")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--service-prefix", required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", args.service_prefix):
        raise ValueError("service prefix must contain lowercase letters, digits and hyphens")
    materialize(args.source, args.output, force=args.force)
    print(f"materialized_panel={args.output}")


if __name__ == "__main__":
    main()
