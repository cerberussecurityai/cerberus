"""Masking of credential-shaped substrings in free text.

Used wherever text that may embed a credential (exception messages, MCP tool
results) is shipped. Always redact BEFORE truncating: a token cut in half can
fall below a pattern's minimum length and survive as a recognisable prefix.
"""

import re

# Credential-shaped substrings. Exception text from LiteLLM can embed provider
# URLs with keys, bearer tokens or URL userinfo. Patterns avoid nested
# quantifiers and bound their repeats so adversarial text stays linear-ish.
#
# URL userinfo: everything between "://" and the LAST "@" of the authority
# (a password may itself contain "@").
_USERINFO = re.compile(r"(?<=://)[^/\s?#]*@")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_BASIC = re.compile(r"\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}")
_SK_TOKEN = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}")
_PROVIDER_KEYS = re.compile(
    r"AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{20,}|AKIA[0-9A-Z]{16}"
)
# name (optionally prefixed, e.g. client_secret, AWS_SECRET_ACCESS_KEY) then
# an "=" or ":" separator with optional quotes/whitespace, then the value.
_SECRET_PARAM = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"([A-Za-z0-9_-]{0,64}(?:key|token|password|secret)[\"']?\s{0,16}[:=]\s{0,16})"
    # A quoted value runs to its closing quote; with no closing quote (cut off,
    # or simply absent) it runs to the end of the line, so an unterminated
    # ``password="hunter2`` is still masked without swallowing the next lines.
    r"(\"[^\"]*\"|\"[^\"\n]*|'[^']*'|'[^'\n]*|[^&\s\"',;]+)",
    re.IGNORECASE,
)


def _mask_param_value(match: re.Match[str]) -> str:
    value = match.group(2)
    quote = value[0] if value[0] in "\"'" else ""
    return f"{match.group(1)}{quote}[REDACTED]{quote}"


# Free text is cut to this many times its final cap BEFORE the regex passes run,
# so a multi-megabyte tool result or error costs a bounded amount of regex time
# on the proxy's event loop. The discarded tail is far beyond the final cap and
# never reaches the event; a credential that starts inside the cap and runs past
# it is still seen whole (or, if enormous, long enough to match) in the slice.
REDACTION_INPUT_FACTOR = 4

# Redaction shrinks text, so a heavily masked slice can end up no longer than
# the final cap, and the caller's truncation would then keep characters right at
# the slice boundary, where a credential cut mid-token is too short for any
# pattern to match. When the slice was cut, that tail is dropped: this many
# characters (longer than any credential prefix the patterns can leave), but
# never more than half of what is left, so a small cap keeps most of its text.
REDACTION_BOUNDARY_MARGIN = 256
TRUNCATION_MARKER = "...[TRUNCATED]"


def redact_bounded(text: str, final_cap: int) -> str:
    """``redact_secrets`` over at most ``REDACTION_INPUT_FACTOR * final_cap`` characters.

    If the input was longer than that, the result also loses its last
    ``REDACTION_BOUNDARY_MARGIN`` characters (see above) plus the whole run of
    non-whitespace left at the end (any partial fragment, of any length), and ends with
    the truncation marker, so the caller's own cap and marker logic still
    applies.
    """
    limit = final_cap * REDACTION_INPUT_FACTOR
    redacted = redact_secrets(text[:limit])
    if len(text) <= limit:
        return redacted
    margin = min(REDACTION_BOUNDARY_MARGIN, len(redacted) // 2)
    kept = redacted[: len(redacted) - margin]
    # Strip the trailing run of non-whitespace by hand (a fragment such as
    # "user:pass@" or "%41" at the edge goes too): a regex anchored at the end is
    # quadratic on a long unbroken run.
    end = len(kept)
    while end and not kept[end - 1].isspace():
        end -= 1
    return kept[:end] + TRUNCATION_MARKER


def redact_secrets(text: str) -> str:
    """Mask credential-shaped substrings in free text; other text is unchanged."""
    text = _USERINFO.sub("[REDACTED]@", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _BASIC.sub("Basic [REDACTED]", text)
    text = _PROVIDER_KEYS.sub("[REDACTED]", text)
    text = _SK_TOKEN.sub("sk-[REDACTED]", text)
    return _SECRET_PARAM.sub(_mask_param_value, text)
