#!/usr/bin/env python3
"""Copy, harden and validate the already tenant-neutral panel runtime."""

from __future__ import annotations

import argparse
import compileall
from pathlib import Path
import re
import shutil
import stat

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "panel"


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected exactly one source block, found {count}")
    return text.replace(old, new, 1)


def harden_public_app(path: Path) -> None:
    """Make optional support caches safe and avoid invented dashboard values."""

    text = path.read_text(encoding="utf-8")

    # Live service truth is already normalized in the source app. Keeping a
    # second textual patch here would make materialization depend on the old UI
    # implementation and would fail after legitimate source refactors.

    text = _replace_once(
        text,
        '''    metrics = _json.loads(support_read_file(SUPPORT_STATUS_DIR, "channel-metrics.json", "{}"))
    day = metrics.get("day") or {}
    hour = metrics.get("hour") or {}

    def f(v):
        try:
            return float(v or 0)
        except Exception:
            return 0.0

    def fmt(v, digits=1):
        try:
            fv = float(v or 0)
            if fv.is_integer():
                return str(int(fv))
            return str(round(fv, digits))
        except Exception:
            return str(v)

    current = f(day.get("current_mbps") or hour.get("current_mbps"))
    cap = f(metrics.get("capacity_mbit") or 250)
    used_pct = max(0.0, min(100.0, current / cap * 100.0 if cap else 0.0))
    free = max(0.0, 100.0 - used_pct)
    peak = f(day.get("peak_mbps"))

    if free >= 50:
        channel_label, channel_cls, channel_text = "свободно", "ok", "Канал работает с хорошим запасом."
    elif free >= 20:
        channel_label, channel_cls, channel_text = "нагрузка", "warn", "Канал заметно загружен, но запас ещё есть."
    else:
        channel_label, channel_cls, channel_text = "плотно", "bad", "Канал близко к пределу, стоит посмотреть нагрузку."
''',
        '''    try:
        metrics = _json.loads(
            support_read_file(SUPPORT_STATUS_DIR, "channel-metrics.json", "{}")
        )
        if not isinstance(metrics, dict):
            metrics = {}
    except Exception:
        metrics = {}

    day = metrics.get("day") or {}
    hour = metrics.get("hour") or {}

    def f(v):
        try:
            return float(v or 0)
        except Exception:
            return 0.0

    def fmt(v, digits=1):
        try:
            fv = float(v or 0)
            if fv.is_integer():
                return str(int(fv))
            return str(round(fv, digits))
        except Exception:
            return str(v)

    current_raw = day.get("current_mbps")
    if current_raw in (None, ""):
        current_raw = hour.get("current_mbps")
    current_known = current_raw not in (None, "")
    current = f(current_raw)

    capacity_raw = metrics.get("capacity_mbit")
    if capacity_raw in (None, "", 0, "0"):
        capacity_raw = CONFIG.channel_capacity_mbit
    capacity_known = capacity_raw not in (None, "", 0, "0")
    cap = f(capacity_raw) if capacity_known else 0.0
    capacity_known = capacity_known and cap > 0

    used_pct = max(0.0, min(100.0, current / cap * 100.0)) if capacity_known else 0.0
    free = max(0.0, 100.0 - used_pct) if capacity_known else None

    peak_raw = day.get("peak_mbps")
    peak_known = peak_raw not in (None, "")
    peak = f(peak_raw)

    channel_current_label = f"{fmt(current)} Мбит/с" if current_known else "данных пока нет"
    channel_peak_value = fmt(peak) if peak_known else "—"

    if not capacity_known:
        channel_label = "не задано"
        channel_cls = "warn"
        channel_text = "Пропускная способность канала не настроена."
        channel_sub = "пропускная способность не задана"
        channel_free_value = "—"
        channel_capacity_value = "—"
    elif free >= 50:
        channel_label, channel_cls, channel_text = "свободно", "ok", "Канал работает с хорошим запасом."
        channel_sub = f"из {fmt(cap)} Мбит/с · свободно {fmt(free)}%"
        channel_free_value = f"{fmt(free)}%"
        channel_capacity_value = fmt(cap)
    elif free >= 20:
        channel_label, channel_cls, channel_text = "нагрузка", "warn", "Канал заметно загружен, но запас ещё есть."
        channel_sub = f"из {fmt(cap)} Мбит/с · свободно {fmt(free)}%"
        channel_free_value = f"{fmt(free)}%"
        channel_capacity_value = fmt(cap)
    else:
        channel_label, channel_cls, channel_text = "плотно", "bad", "Канал близко к пределу, стоит посмотреть нагрузку."
        channel_sub = f"из {fmt(cap)} Мбит/с · свободно {fmt(free)}%"
        channel_free_value = f"{fmt(free)}%"
        channel_capacity_value = fmt(cap)
''',
        "safe home channel metrics",
    )

    text = _replace_once(
        text,
        '''  <div class="home-channel-main">{esc(fmt(current))} Мбит/с</div>
  <div class="home-channel-sub">из {esc(fmt(cap))} Мбит/с · свободно {esc(fmt(free))}%</div>
  <div class="home-channel-bar" style="--home-used:{used_pct:.1f}%"><span></span></div>
  <p class="muted">{esc(channel_text)}</p>
  <div class="home-mini-grid">
    <div class="home-mini"><b>{esc(fmt(peak))}</b><span>пик сегодня</span></div>
    <div class="home-mini"><b>{esc(fmt(free))}%</b><span>запас</span></div>
    <div class="home-mini"><b>{esc(fmt(cap))}</b><span>канал Мбит/с</span></div>
  </div>
''',
        '''  <div class="home-channel-main">{esc(channel_current_label)}</div>
  <div class="home-channel-sub">{esc(channel_sub)}</div>
  <div class="home-channel-bar" style="--home-used:{used_pct:.1f}%"><span></span></div>
  <p class="muted">{esc(channel_text)}</p>
  <div class="home-mini-grid">
    <div class="home-mini"><b>{esc(channel_peak_value)}</b><span>пик сегодня</span></div>
    <div class="home-mini"><b>{esc(channel_free_value)}</b><span>запас</span></div>
    <div class="home-mini"><b>{esc(channel_capacity_value)}</b><span>канал Мбит/с</span></div>
  </div>
''',
        "honest home channel display",
    )

    text = _replace_once(
        text,
        '''    capacity = fnum(hist.get("capacity_mbit") or metrics.get("capacity_mbit") or 250, 250)
    current = fnum(metrics.get("current_mbps") or day.get("current_mbps") or (hist.get("last") or {}).get("current_mbps"))
    used_pct = 0 if capacity <= 0 else max(0, min(100, current / capacity * 100))
    free_pct = max(0, 100 - used_pct)

    if used_pct >= 85:
        status, status_cls, note = "Плотно", "bad", "Канал близко к пределу."
    elif used_pct >= 55:
        status, status_cls, note = "Нагрузка", "warn", "Канал заметно загружен, но запас ещё есть."
    else:
        status, status_cls, note = "Свободно", "ok", "Канал работает с хорошим запасом."
''',
        '''    capacity_raw = hist.get("capacity_mbit") or metrics.get("capacity_mbit") or CONFIG.channel_capacity_mbit
    capacity = fnum(capacity_raw)
    capacity_known = capacity_raw not in (None, "", 0, "0") and capacity > 0
    current = fnum(metrics.get("current_mbps") or day.get("current_mbps") or (hist.get("last") or {}).get("current_mbps"))
    used_pct = max(0, min(100, current / capacity * 100)) if capacity_known else 0
    free_pct = max(0, 100 - used_pct) if capacity_known else 0

    if not capacity_known:
        status, status_cls, note = "Не задано", "warn", "Пропускная способность канала не настроена."
        capacity_sub = "пропускная способность не задана"
    elif used_pct >= 85:
        status, status_cls, note = "Плотно", "bad", "Канал близко к пределу."
        capacity_sub = f"из {mb(capacity)} · свободно {free_pct:.1f}%"
    elif used_pct >= 55:
        status, status_cls, note = "Нагрузка", "warn", "Канал заметно загружен, но запас ещё есть."
        capacity_sub = f"из {mb(capacity)} · свободно {free_pct:.1f}%"
    else:
        status, status_cls, note = "Свободно", "ok", "Канал работает с хорошим запасом."
        capacity_sub = f"из {mb(capacity)} · свободно {free_pct:.1f}%"
''',
        "honest channel capacity calculation",
    )

    text = _replace_once(
        text,
        '''<div class="cr-hero"><div><div class="cr-speed">{esc(mb(current))}</div><div class="cr-sub">из {esc(mb(capacity))} · свободно {esc(f'{free_pct:.1f}%')}</div><div class="cr-meter"><i style="width:{esc(f'{used_pct:.1f}')}%"></i></div><div class="cr-sub">{esc(note)}</div></div>
''',
        '''<div class="cr-hero"><div><div class="cr-speed">{esc(mb(current))}</div><div class="cr-sub">{esc(capacity_sub)}</div><div class="cr-meter"><i style="width:{esc(f'{used_pct:.1f}')}%"></i></div><div class="cr-sub">{esc(note)}</div></div>
''',
        "honest channel capacity display",
    )

    path.write_text(text, encoding="utf-8")


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

    app_path = output / "app.py"
    if not app_path.is_file():
        raise FileNotFoundError(f"materialized panel app not found: {app_path}")
    harden_public_app(app_path)

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
