import pytest

pytest.importorskip("mcp")
pytest.importorskip("httpx")

from mcp.types import CallToolResult, TextContent  # noqa: E402

from orchestrator.gateway_client import GatewayError, unwrap  # noqa: E402


def result(text="", structured=None, error=False):
    return CallToolResult(content=[TextContent(type="text", text=text)] if text else [],
                          structuredContent=structured, isError=error)


def test_structured_content_is_returned():
    assert unwrap(result(structured={"a": 1})) == {"a": 1}


def test_json_text_is_the_fallback():
    assert unwrap(result(text='{"a": 1}')) == {"a": 1}


@pytest.mark.parametrize("bad,message", [
    (result(text="trivy worker failed", error=True), "trivy worker failed"),   # error from the gateway
    (result(text="not json"), "not JSON"),
    (result(text="[1, 2]"), "unexpected"),
])
def test_errors_and_unexpected_shapes_raise_gateway_error(bad, message):
    with pytest.raises(GatewayError, match=message):
        unwrap(bad)


def test_long_error_text_is_cut():
    with pytest.raises(GatewayError) as e:
        unwrap(result(text="x" * 1000, error=True))
    assert len(str(e.value)) == 300
