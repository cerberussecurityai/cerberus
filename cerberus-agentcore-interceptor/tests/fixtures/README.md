# Fixtures

`<name>.input.json` is one interceptor invocation — the envelope the gateway
sent plus its client context — recorded against a real AgentCore Gateway and
scrubbed: account `123456789012`, RFC 5737 addresses, JWT signatures removed,
and request, session and completion ids replaced by placeholders. Base64
bodies are scrubbed the same way once decoded, along with the credentials and
internal hostnames they echo. Trace ids are kept as recorded.
`test_fixtures_scrubbed.py` enforces that.
A `-response` case is a RESPONSE invocation, of the same call as the request
case its name extends where there is one.

`<name>.event.json` beside it is the source event the mapper builds for that
phase. Unsupported-version cases carry none, because nothing is captured for
them.

Regenerate the goldens with `python tests/regenerate.py` when the contract
changes. Cases with a `note` field were edited by hand; the note says how.
An `options` field sets the mapper options a case runs with.
