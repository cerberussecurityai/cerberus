# Fixtures

`<name>.input.json` is one interceptor invocation — the envelope the gateway
sent plus its client context — recorded against a real AgentCore Gateway and
scrubbed: account `123456789012`, RFC 5737 addresses, JWT signatures removed.
`test_fixtures_scrubbed.py` enforces that.

`<name>.event.json` beside it is the source event the mapper builds. Request
cases carry one; response-phase and unsupported-version cases do not, because
nothing is captured for them.

Regenerate the goldens with `python tests/regenerate.py` when the contract
changes. Cases with a `note` field were edited by hand; the note says how.
