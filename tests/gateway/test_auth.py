import pytest

from gateway.auth import AuthMiddleware

TOKEN = "t" * 16


@pytest.fixture
def inner_calls():
    return []


@pytest.fixture
def app(inner_calls):
    async def inner(scope, receive, send):
        inner_calls.append(scope["type"])
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

    return AuthMiddleware(inner, TOKEN, exempt_paths={"/health"})


def status(sent):
    return sent[0]["status"]


def test_correct_bearer_token_reaches_the_app(app, asgi_request, inner_calls):
    sent = asgi_request(app, headers=[(b"authorization", f"Bearer {TOKEN}".encode())])
    assert status(sent) == 200
    assert inner_calls == ["http"]


@pytest.mark.parametrize("headers", [
    [],                                              # no header
    [(b"authorization", b"Bearer wrong-token-xxxx")],  # wrong token
    [(b"authorization", TOKEN.encode())],              # missing "Bearer " prefix
])
def test_missing_or_wrong_token_gets_401_and_never_reaches_the_app(app, asgi_request, inner_calls, headers):
    sent = asgi_request(app, headers=headers)
    assert status(sent) == 401
    assert inner_calls == []


def test_exempt_path_needs_no_token(app, asgi_request):
    assert status(asgi_request(app, path="/health")) == 200
