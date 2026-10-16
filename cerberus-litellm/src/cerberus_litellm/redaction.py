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
    r"(\"[^\"]*\"|'[^']*'|[^&\s\"',;]+)",
    re.IGNORECASE,
)


def _mask_param_value(match: re.Match[str]) -> str:
    value = match.group(2)
    quote = value[0] if value[0] in "\"'" else ""
    return f"{match.group(1)}{quote}[REDACTED]{quote}"


def redact_secrets(text: str) -> str:
    """Mask credential-shaped substrings in free text; other text is unchanged."""
    text = _USERINFO.sub("[REDACTED]@", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _BASIC.sub("Basic [REDACTED]", text)
    text = _PROVIDER_KEYS.sub("[REDACTED]", text)
    text = _SK_TOKEN.sub("sk-[REDACTED]", text)
    return _SECRET_PARAM.sub(_mask_param_value, text)
