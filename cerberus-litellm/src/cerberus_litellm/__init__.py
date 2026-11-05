"""cerberus-litellm: LiteLLM proxy callback plugin for the Cerberus platform.

Register in the proxy config::

    litellm_settings:
      callbacks: ["cerberus_litellm.handler"]

LiteLLM resolves that string as ``getattr(import_module("cerberus_litellm"),
"handler")``, so the logger instance is exposed as a lazily built package
attribute (PEP 562). Nothing is constructed, and no environment is read, until
the proxy asks for it — tests import the class from ``cerberus_litellm.plugin``
directly and build their own instances.
"""

import threading
from typing import Any

__version__ = "0.1.0"

_handler: Any = None
_handler_lock = threading.Lock()


def __getattr__(name: str) -> Any:
    if name == "handler":
        global _handler
        if _handler is None:
            # Double-checked: two threads racing the first access must not each
            # build a logger (each would own a queue, a sink and an exit hook).
            with _handler_lock:
                if _handler is None:
                    from .plugin import CerberusLogger

                    _handler = CerberusLogger()
        return _handler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
