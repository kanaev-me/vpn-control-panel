#!/usr/bin/env python3
"""Bounded parsing for application/x-www-form-urlencoded POST bodies."""

from __future__ import annotations

from urllib.parse import parse_qs


DEFAULT_MAX_FORM_BYTES = 4096
FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


class FormBodyError(ValueError):
    """A safe client error raised before form data reaches a route handler."""

    status_code = 400
    public_message = "Некорректное тело запроса."


class InvalidContentLength(FormBodyError):
    public_message = "Некорректный размер тела запроса."


class RequestBodyTooLarge(FormBodyError):
    status_code = 413
    public_message = "Тело запроса слишком большое."


class IncompleteRequestBody(FormBodyError):
    public_message = "Тело запроса передано не полностью."


class UnsupportedMediaType(FormBodyError):
    status_code = 415
    public_message = "Поддерживаются только обычные HTML-формы."


class UnsupportedTransferEncoding(FormBodyError):
    public_message = "Потоковая передача тела запроса не поддерживается."


class UnsupportedContentEncoding(FormBodyError):
    status_code = 415
    public_message = "Сжатое тело запроса не поддерживается."


def _header_values(headers, name: str) -> list[str]:
    """Return all non-empty values from dict- or Message-like headers."""

    try:
        values = headers.get_all(name)
    except AttributeError:
        value = headers.get(name)
        values = [] if value is None else [value]

    if values is None:
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def validate_form_framing(headers) -> None:
    """Reject ambiguous framing before any request bytes are consumed."""

    transfer_encodings = _header_values(headers, "Transfer-Encoding")
    if transfer_encodings:
        raise UnsupportedTransferEncoding()

    content_encodings = _header_values(headers, "Content-Encoding")
    if any(value.lower() not in {"", "identity"} for value in content_encodings):
        raise UnsupportedContentEncoding()

    media_types = _header_values(headers, "Content-Type")
    if len(media_types) > 1:
        raise UnsupportedMediaType()
    if media_types:
        media_type = media_types[0].split(";", 1)[0].strip().lower()
        if media_type != FORM_MEDIA_TYPE:
            raise UnsupportedMediaType()


def parse_content_length(headers, *, max_bytes: int = DEFAULT_MAX_FORM_BYTES) -> int:
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")

    values = _header_values(headers, "Content-Length")
    if not values:
        return 0
    if len(values) != 1:
        raise InvalidContentLength()

    raw = values[0]
    try:
        length = int(raw, 10)
    except (TypeError, ValueError) as exc:
        raise InvalidContentLength() from exc

    if length < 0:
        raise InvalidContentLength()
    if length > max_bytes:
        raise RequestBodyTooLarge()
    return length


def read_urlencoded_form(headers, stream, *, max_bytes: int = DEFAULT_MAX_FORM_BYTES):
    """Read exactly one bounded form body and return parse_qs-compatible data."""

    validate_form_framing(headers)
    length = parse_content_length(headers, max_bytes=max_bytes)
    body = stream.read(length) if length else b""

    if len(body) != length:
        raise IncompleteRequestBody()

    return parse_qs(body.decode("utf-8", "replace"))
