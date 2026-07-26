#!/usr/bin/env python3
"""Fail if a public checkout contains secrets or deployment artifacts."""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".p12", ".pfx", ".pem", ".key", ".mobileconfig", ".sswan", ".ovpn"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"(?i)\b(?:https?|ssh)://[^/\s:@]+:[^/\s@]+@"),
)

findings = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
        continue
    if path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name in {"panel.env", ".env"}:
        findings.append(f"forbidden file: {path.relative_to(ROOT)}")
        continue
    data = path.read_bytes()
    for pattern in SECRET_PATTERNS:
        if pattern.search(data):
            findings.append(f"secret-like content: {path.relative_to(ROOT)}")
            break

if findings:
    print("Public snapshot check failed:", file=sys.stderr)
    for finding in findings:
        print(f"- {finding}", file=sys.stderr)
    raise SystemExit(1)
print("public_snapshot=ok")
