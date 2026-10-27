import pytest

from gateway.approval import ApprovalError, ApprovalVerifier, issue_approval

SECRET = b"s" * 32
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def token(**kw):
    return issue_approval(SECRET, tool="slim", image_digest=DIGEST, now=1000, **kw)


def verifier(now=1000, secret=SECRET):
    return ApprovalVerifier(secret, clock=lambda: now)


def test_valid_token_is_accepted():
    verifier().verify(token(), tool="slim", image_digest=DIGEST)  # no exception


def test_token_can_only_be_used_once():
    v = verifier()
    t = token()
    v.verify(t, tool="slim", image_digest=DIGEST)
    with pytest.raises(ApprovalError, match="already used"):
        v.verify(t, tool="slim", image_digest=DIGEST)


@pytest.mark.parametrize("tool,digest", [("bench", DIGEST), ("slim", OTHER_DIGEST)])
def test_token_is_bound_to_tool_and_digest(tool, digest):
    with pytest.raises(ApprovalError, match="different tool or image"):
        verifier().verify(token(), tool=tool, image_digest=digest)


def test_expired_token_is_rejected():
    with pytest.raises(ApprovalError, match="expired"):
        verifier(now=1000 + 601).verify(token(), tool="slim", image_digest=DIGEST)  # default ttl is 600s


@pytest.mark.parametrize("bad", ["", "garbage", "a.b", "....", "e30.e30"])
def test_malformed_token_is_rejected(bad):
    with pytest.raises(ApprovalError):
        verifier().verify(bad, tool="slim", image_digest=DIGEST)


def test_token_signed_with_another_secret_is_rejected():
    with pytest.raises(ApprovalError, match="signature"):
        verifier(secret=b"x" * 32).verify(token(), tool="slim", image_digest=DIGEST)
