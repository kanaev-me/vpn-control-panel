#!/usr/bin/env python3
"""Session-bound CSRF tokens and HTML form injection for the panel."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets


CSRF_FIELD_NAME = "_csrf"
_MAX_SESSION_ID_LENGTH = 512
_PROCESS_SECRET = secrets.token_bytes(32)
_FORM_OPEN_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_POST_METHOD_RE = re.compile(
    r"\bmethod\s*=\s*(?:\"post\"|'post'|post)(?=\s|/?>)",
    re.IGNORECASE,
)
_LOGIN_ACTION_RE = re.compile(
    r"\baction\s*=\s*(?:\"/login(?:[?#][^\"]*)?\"|'/login(?:[?#][^']*)?'|/login(?=\s|/?>))",
    re.IGNORECASE,
)


def token_for_session(session_id: str) -> str:
    """Return the process-local CSRF token bound to one server session."""

    session_id = str(session_id or "")
    if not session_id or len(session_id) > _MAX_SESSION_ID_LENGTH:
        return ""
    return hmac.new(
        _PROCESS_SECRET,
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def token_is_valid(session_id: str, submitted_token: str) -> bool:
    """Compare a submitted token without timing-sensitive string equality."""

    expected = token_for_session(session_id)
    submitted_token = str(submitted_token or "")
    return bool(expected and submitted_token) and hmac.compare_digest(
        expected,
        submitted_token,
    )


def inject_post_form_tokens(html_text: str, token: str) -> str:
    """Inject a hidden token into authenticated POST forms.

    The public login form is deliberately excluded. The operation runs at the
    final response boundary, after historical presentation wrappers have built
    their HTML, so individual legacy page functions do not need to know about
    CSRF state.
    """

    html_text = str(html_text or "")
    token = str(token or "")
    if not html_text or not token:
        return html_text

    hidden = (
        f'<input type="hidden" name="{CSRF_FIELD_NAME}" value="{token}">'
    )

    def replace(match: re.Match[str]) -> str:
        opening_tag = match.group(0)
        if not _POST_METHOD_RE.search(opening_tag):
            return opening_tag
        if _LOGIN_ACTION_RE.search(opening_tag):
            return opening_tag
        return opening_tag + hidden

    return _FORM_OPEN_RE.sub(replace, html_text)
