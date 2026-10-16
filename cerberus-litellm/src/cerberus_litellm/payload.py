"""Read-only accessors over LiteLLM's ``standard_logging_object``.

Everything the mappers consume comes through here, so the set of payload
fields the plugin reads is auditable in one place. Nothing else in the hook
``kwargs`` is touched: the customer's upstream provider key sits there.

Every accessor tolerates junk (missing keys, wrong types) and returns None
instead of raising — a logging callback must never take the proxy down.
"""

import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


def get(slo: Any, *path: str, default: Any = None) -> Any:
    """Walk nested mappings; return ``default`` at the first miss."""
    node = slo
    for key in path:
        if not isinstance(node, Mapping):
            return default
        node = node.get(key)
    return default if node is None else node


def metadata(slo: Any) -> dict[str, Any]:
    md = get(slo, "metadata")
    return dict(md) if isinstance(md, Mapping) else {}


def call_type(slo: Any) -> str:
    value = get(slo, "call_type")
    return value if isinstance(value, str) else ""


def status(slo: Any) -> str:
    return "error" if get(slo, "status") == "failure" else "ok"


def identity(slo: Any) -> dict[str, Any]:
    md = metadata(slo)
    end_user = md.get("user_api_key_end_user_id") or get(slo, "end_user")
    return {
        "litellm_key_hash": _str_or_none(md.get("user_api_key_hash")),
        "litellm_key_alias": _str_or_none(md.get("user_api_key_alias")),
        "litellm_team_id": _str_or_none(md.get("user_api_key_team_id")),
        "litellm_team_alias": _str_or_none(md.get("user_api_key_team_alias")),
        "litellm_org_id": _str_or_none(md.get("user_api_key_org_id")),
        "litellm_user_id": _str_or_none(md.get("user_api_key_user_id")),
        "litellm_end_user_id": _str_or_none(end_user),
    }


def custom_headers(slo: Any) -> dict[str, str]:
    raw = metadata(slo).get("requester_custom_headers")
    if not isinstance(raw, Mapping):
        return {}
    return {
        str(key).lower(): value
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, str)
    }


def iso_timestamp(epoch: Any) -> str | None:
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _delta_ms(slo: Any, start_key: str, end_key: str) -> float | None:
    start, end = get(slo, start_key), get(slo, end_key)
    if isinstance(start, bool) or isinstance(end, bool):
        return None
    if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
        return None
    delta = (float(end) - float(start)) * 1000.0
    # NaN/inf would serialise into the batch and get the whole batch rejected.
    return round(delta, 3) if math.isfinite(delta) else None


def duration_ms(slo: Any) -> float | None:
    return _delta_ms(slo, "startTime", "endTime")


def ttft_ms(slo: Any) -> float | None:
    return _delta_ms(slo, "startTime", "completionStartTime")


def error_info(slo: Any) -> dict[str, Any]:
    info = get(slo, "error_information")
    info = info if isinstance(info, Mapping) else {}
    return {
        "error_message": _str_or_none(info.get("error_message")),
        "error_class": _str_or_none(info.get("error_class")),
        "error_code": _str_or_none(info.get("error_code")),
        "error_normalized": _str_or_none(info.get("normalized_error")),
    }


def user_id(slo: Any, sources: tuple[str, ...]) -> str | None:
    ident = identity(slo)
    lookup: dict[str, str | None] = {
        "end_user": ident["litellm_end_user_id"],
        "user_id": ident["litellm_user_id"],
        "key_alias": ident["litellm_key_alias"],
        "team_alias": ident["litellm_team_alias"],
    }
    for source in sources:
        value = lookup.get(source)
        if value:
            return value
    return None


def session_id(slo: Any, header: str) -> str | None:
    value = _str_or_none(get(slo, "session_id"))
    if value:
        return value
    return _str_or_none(custom_headers(slo).get(header.lower()))


def turn_id(slo: Any, header: str) -> str | None:
    return _str_or_none(custom_headers(slo).get(header.lower()))


def host_only(url: Any) -> str | None:
    """Hostname of a provider URL; credentials and query strings never ship."""
    if not isinstance(url, str) or not url:
        return None
    try:
        return urlsplit(url).hostname or None
    except ValueError:
        return None


def w3c_trace_id(traceparent: Any) -> str | None:
    if not isinstance(traceparent, str):
        return None
    match = _TRACEPARENT.match(traceparent.strip().lower())
    return match.group(1) if match else None


def _str_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value != "":
        return value
    return None
