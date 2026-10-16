"""Throwaway LiteLLM CustomLogger that dumps every hook payload to disk.

This is the "path A" probe for the LiteLLM capture comparison: it records exactly what an
in-process callback plugin would see, unmodified, so the capture can be
scored against the OTel v2 export of the same traffic. Nothing here is
production code.

Loaded by LiteLLM from the config directory:
    litellm_settings:
      callbacks: ["dump_logger.handler"]

Each hook writes one JSON file to $SPIKE_CAPTURE_DIR (default /captures/plugin):
    NNN_<hook>_<call_type>.json
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import threading
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

CAPTURE_DIR = os.environ.get("SPIKE_CAPTURE_DIR", "/captures/plugin")
_SKIP_KEYS = {"litellm_logging_obj", "logger_fn", "acompletion"}
_MAX_DEPTH = 14
_SECRET_KEYS = {
    "api_key", "apikey", "authorization", "proxy-authorization", "x-api-key",
    "x-litellm-api-key", "token", "access_token", "refresh_token", "id_token",
    "password", "secret", "client_secret", "cookie", "set-cookie",
}
_SECRET_SUFFIXES = ("_api_key", "_token", "_secret", "_password")
_SECRET_VALUE = re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{8,}|Bearer\s+\S+)")
_SAFE = re.compile(r"[^A-Za-z0-9_-]")


def _is_secret_key(key: Any) -> bool:
    k = str(key).lower()
    return k in _SECRET_KEYS or k.endswith(_SECRET_SUFFIXES)


def _safe_name(value: Any) -> str:
    """Request-derived text is reduced to [A-Za-z0-9_-], max 40 chars."""
    return _SAFE.sub("_", str(value or ""))[:40] or "unknown"


_seq = 0
_lock = threading.Lock()


def _jsonable(obj: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return f"<max depth {type(obj).__name__}>"
    if isinstance(obj, str):
        return _SECRET_VALUE.sub("<redacted>", obj)
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, bytes):
        return {"__bytes__": len(obj)}
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {
            str(k): ("<redacted>" if _is_secret_key(k) else _jsonable(v, depth + 1))
            for k, v in obj.items()
            if k not in _SKIP_KEYS
        }
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in obj]
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return {"__type__": type(obj).__name__, **_jsonable(dump(), depth + 1)}
        except Exception as exc:  # noqa: BLE001
            return {"__type__": type(obj).__name__, "__model_dump_error__": repr(exc)}
    if hasattr(obj, "__dict__") and not callable(obj):
        try:
            return {"__type__": type(obj).__name__, **_jsonable(vars(obj), depth + 1)}
        except Exception as exc:  # noqa: BLE001
            return {"__type__": type(obj).__name__, "__vars_error__": repr(exc)}
    return {"__repr__": repr(obj)[:2000]}


def _write(hook: str, call_type: Any, payload: dict[str, Any]) -> None:
    global _seq
    with _lock:
        _seq += 1
        seq = _seq
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    name = f"{seq:03d}_{_safe_name(hook)}_{_safe_name(call_type)}.json"
    path = os.path.join(CAPTURE_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_jsonable(payload), fh, indent=2, sort_keys=True, default=str)
    print(f"[dump_logger] wrote {path}", flush=True)


class DumpLogger(CustomLogger):
    # ---- logging hooks -------------------------------------------------
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            _write(
                "success",
                kwargs.get("call_type"),
                {
                    "start_time": start_time,
                    "end_time": end_time,
                    "response_obj": response_obj,
                    "standard_logging_object": kwargs.get("standard_logging_object"),
                    "kwargs": kwargs,
                },
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[dump_logger] success dump failed: {exc!r}", flush=True)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        try:
            _write(
                "failure",
                kwargs.get("call_type"),
                {
                    "start_time": start_time,
                    "end_time": end_time,
                    "response_obj": response_obj,
                    "exception": kwargs.get("exception"),
                    "traceback": kwargs.get("traceback_exception"),
                    "standard_logging_object": kwargs.get("standard_logging_object"),
                    "kwargs": kwargs,
                },
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[dump_logger] failure dump failed: {exc!r}", flush=True)

    # ---- proxy call hooks (observe only) -------------------------------
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        try:
            _write(
                "pre_call",
                call_type,
                {"call_type": call_type, "user_api_key_dict": user_api_key_dict, "data": data},
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[dump_logger] pre_call dump failed: {exc!r}", flush=True)
        return data

    # ---- MCP hooks -----------------------------------------------------
    async def async_post_mcp_tool_call_hook(self, kwargs, response_obj, start_time, end_time):
        try:
            _write(
                "mcp_post",
                "mcp_tool_call",
                {"start_time": start_time, "end_time": end_time, "response_obj": response_obj, "kwargs": kwargs},
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[dump_logger] mcp_post dump failed: {exc!r}", flush=True)
        return None


handler = DumpLogger()
