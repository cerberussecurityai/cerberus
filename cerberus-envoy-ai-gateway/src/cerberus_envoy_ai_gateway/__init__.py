"""Cerberus bridge for Envoy AI Gateway.

Receives OTLP/HTTP traces from the Envoy AI Gateway extproc, maps LLM and
MCP spans to Cerberus events, and ships them to the Cerberus backend's
batch ingest endpoint.
"""

__version__ = "0.1.0"
