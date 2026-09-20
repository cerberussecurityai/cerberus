"""CloudWatch metrics, emitted as embedded-metric-format log lines.

EMF keeps the handler free of a metrics API call on the request path: the log
line is the metric.
"""

from __future__ import annotations

import json
import sys
import time
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
REASON_OVERSIZE = "oversize"
REASON_HANDLER = "handler_error"


def count(metric: str, reason: str = "", **fields: Any) -> None:
    """Emit one count of a metric. Never raises; a metric is not worth a request."""
    try:
        record: dict[str, Any] = {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": NAMESPACE,
                        "Dimensions": [["Reason"]] if reason else [[]],
                        "Metrics": [{"Name": metric, "Unit": "Count"}],
                    }
                ],
            },
            metric: 1,
        }
        if reason:
            record["Reason"] = reason
        record.update(fields)
        print(json.dumps(record, default=str), file=sys.stdout, flush=False)
    except Exception:
        pass
