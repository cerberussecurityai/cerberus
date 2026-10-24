"""
Cerberus MCP Configuration

Shared configuration constants for the cerberus-mcp package.
"""

import os

DEBUG_ENABLED = os.getenv('CERBERUS_DEBUG', 'false').lower() in ('true', '1', 'yes')

# Maximum length for string values in captured arguments
MAX_ARG_STRING_LENGTH = 200

# Maximum length for result summary strings
MAX_RESULT_LENGTH = 100

# Maximum number of events to buffer before dropping
EVENT_QUEUE_MAXSIZE = 10_000

# Package version and user agent
VERSION = "0.1.3"
USER_AGENT = f"cerberus-mcp/{VERSION}"
