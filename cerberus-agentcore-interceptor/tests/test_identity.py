import base64
import json

from cerberus_agentcore_interceptor import identity


def token(claims: dict) -> str:
    def part(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    return ".".join(
        [
            part(json.dumps({"alg": "RS256"}).encode()),
            part(json.dumps(claims).encode()),
            "SIGNATURE-REMOVED",
        ]
    )


def headers(value: str) -> dict:
    return {"Authorization": value}


def test_jwt_reads_the_configured_claim():
    who = identity.resolve(
        identity.JWT,
        headers("Bearer " + token({"sub": "user-1", "username": "alice", "client_id": "app"})),
    )
    assert who.user_id == "user-1"
    assert who.detail == {
        "mode": "jwt",
        "claim": "sub",
        "username": "alice",
        "client_id": "app",
    }


def test_jwt_accepts_a_token_without_the_bearer_scheme():
    who = identity.resolve(identity.JWT, headers(token({"sub": "user-2"})))
    assert who.user_id == "user-2"


def test_jwt_claim_override():
    who = identity.resolve(
        identity.JWT, headers("Bearer " + token({"sub": "s", "email": "a@b.c"})), "email"
    )
    assert who.user_id == "a@b.c"


def test_jwt_numeric_claim_becomes_text():
    who = identity.resolve(identity.JWT, headers("Bearer " + token({"sub": 42})))
    assert who.user_id == "42"


def test_jwt_records_no_user_when_the_token_is_unreadable():
    for value in ("Bearer not.a.jwt", "Bearer onlyonepart", "Bearer a.b"):
        who = identity.resolve(identity.JWT, headers(value))
        assert who.user_id == ""
        assert who.detail["status"] == "malformed"


def test_jwt_without_a_header():
    who = identity.resolve(identity.JWT, {})
    assert who.user_id == ""
    assert who.detail == {"mode": "jwt", "status": "missing"}


def test_jwt_missing_claim_leaves_the_user_empty():
    who = identity.resolve(identity.JWT, headers("Bearer " + token({"username": "alice"})))
    assert who.user_id == ""
    assert who.detail["username"] == "alice"


def test_token_never_appears_in_the_detail():
    raw = token({"sub": "user-1"})
    who = identity.resolve(identity.JWT, headers("Bearer " + raw))
    assert raw not in json.dumps(who.detail)


def test_sigv4_records_the_access_key_id_only():
    who = identity.resolve(
        identity.SIGV4,
        headers(
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260101/us-west-2/"
            "bedrock-agentcore/aws4_request, SignedHeaders=host, Signature=abc"
        ),
    )
    assert who.user_id == ""
    assert who.detail == {"mode": "sigv4", "access_key_id": "AKIAEXAMPLE"}


def test_sigv4_without_a_signature():
    who = identity.resolve(identity.SIGV4, {})
    assert who.detail == {"mode": "sigv4", "status": "missing"}


def test_none_mode_reads_nothing():
    who = identity.resolve(identity.NONE, headers("Bearer " + token({"sub": "claimed"})))
    assert who.user_id == ""
    assert who.detail == {"mode": "none"}


def test_unknown_mode_behaves_like_none():
    who = identity.resolve("something-else", headers("Bearer " + token({"sub": "s"})))
    assert who.user_id == ""


def test_claims_are_capped():
    who = identity.resolve(identity.JWT, headers("Bearer " + token({"sub": "s" * 900})))
    assert len(who.user_id) == identity.MAX_CLAIM_CHARS
