#!/usr/bin/env python3
"""Update one characterization assertion for the new dashboard architecture."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tests" / "test_materialize_tenant_panel.py"

old = '            self.assertIn("live_state = service_state(key)", app_text)\n'
new = (
    '            self.assertTrue((output / "dashboard_status.py").is_file())\n'
    '            self.assertIn("normalize_dashboard_data(", app_text)\n'
    '            self.assertIn("service_state=service_state", app_text)\n'
)

text = PATH.read_text(encoding="utf-8")
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise RuntimeError("materializer dashboard assertion source block not found")
PATH.write_text(text, encoding="utf-8")
print("live_session_test_fix=applied")
