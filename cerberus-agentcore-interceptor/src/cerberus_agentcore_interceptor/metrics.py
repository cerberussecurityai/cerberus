"""CloudWatch metrics, emitted as embedded-metric-format log lines.

EMF keeps the handler free of a metrics API call on the request path: the log
line is the metric.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import Any

NAMESPACE = "Cerberus/AgentCoreInterceptor"

CAPTURED = "Captured"
CAPTURE_DROPPED = "CaptureDropped"
UNKNOWN_INPUT_VERSION = "UnknownInputVersion"
UNEXPECTED_PHASE = "UnexpectedPhase"
UNKNOWN_SHAPE = "UnknownShape"

# Why a capture did not reach Firehose. Closed set: these are alarm dimensions.
REASON_SINK = "sink_error"
REASON_THROTTLE = "throttle"
REASON_TIMEOUT = "timeout"
REASON_DEADLINE = "deadline"
REASON_OVERSIZE = "oversize"
REASON_HANDLER = "handler_error"
REASON_CONFIG = "config_invalid"


def count(metric: str, reason: str = "", **fields: Any) -> None:
    """Emit one count of a metric. Never raises; a metric is not worth a request."""
    try:
        now = datetime.now(UTC)
        record: dict[str, Any] = {
            **fields,
            "_aws": {
                "Timestamp": int(now.timestamp() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": NAMESPACE,
                        # The dimensionless series sums every reason, so one alarm covers them.
                        "Dimensions": [[], ["Reason"]] if reason else [[]],
                        "Metrics": [{"Name": metric, "Unit": "Count"}],
                    }
                ],
            },
            # Lambda filters only logging-module lines by level, so a printed metric
            # counts at any ApplicationLogLevel. This only grades the line for queries.
            "level": "INFO" if metric == CAPTURED else "WARN",
            "timestamp": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            metric: 1,
        }
        if reason:
            record["Reason"] = reason
        # A line still buffered when the function times out is never logged.
        print(json.dumps(record, default=str), file=sys.stdout, flush=True)
    except Exception:
        pass
