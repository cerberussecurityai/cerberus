"""Rate-limited warnings, so one noisy input cannot flood the proxy log."""

import logging
import time
from collections.abc import Callable
from typing import Any


class LogThrottle:
    """Emit at most one warning per ``interval`` seconds; count the rest."""

    def __init__(self, interval: float = 60.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._interval = interval
        self._clock = clock
        self._last: float | None = None
        self.suppressed = 0

    def warn(
        self, logger: logging.Logger, message: str, *args: Any, exc_info: bool = False
    ) -> bool:
        """Log ``message % args`` at WARNING unless one was logged recently."""
        now = self._clock()
        if self._last is not None and now - self._last < self._interval:
            self.suppressed += 1
            return False
        self._last = now
        if self.suppressed:
            message += " (%d similar warnings suppressed)"
            args = (*args, self.suppressed)
            self.suppressed = 0
        logger.warning(message, *args, exc_info=exc_info)
        return True
