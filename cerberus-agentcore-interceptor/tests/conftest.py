import os

# The handler reads its configuration at import, so this has to be set before
# any test module imports it.
os.environ.setdefault("CERBERUS_FIREHOSE_STREAM", "cerberus-capture-test")
