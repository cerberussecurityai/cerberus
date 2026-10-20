"""Cerberus interceptor for AWS Bedrock AgentCore Gateway."""

from .bounding import CaptureDeadlineExceeded

__version__ = "0.2.0"

__all__ = ["CaptureDeadlineExceeded", "__version__"]
