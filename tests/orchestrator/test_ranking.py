import asyncio

import pytest

from orchestrator.contract import Finding
from orchestrator.ranking import rank_deterministic, rank_with_llm, validate_llm_output

F = [Finding(id="CVE-1", pkg="a", severity="HIGH"), Finding(id="CVE-2", pkg="b", severity="HIGH"),
     Finding(id="CVE-3", pkg="c", severity="CRITICAL")]


def ranked(usage=None, exposure="public"):
    return rank_deterministic(F, usage or {}, exposure)


def test_severity_usage_and_exposure_decide_the_order():
    usage = {"CVE-1:a": "used", "CVE-2:b": "undetermined", "CVE-3:c": "not_reachable"}
    result = ranked(usage)
    # HIGH used 3.0 > HIGH undetermined 2.4 > CRITICAL but not reachable 1.2
    assert [r["id"] for r in result] == ["CVE-1", "CVE-2", "CVE-3"]
    assert [r["score"] for r in result] == [3.0, 2.4, 1.2]


def test_internal_exposure_lowers_the_score():
    assert ranked({"CVE-1:a": "used"}, exposure="internal")[0]["score"] < ranked({"CVE-1:a": "used"})[0]["score"]


def test_missing_usage_is_undetermined_not_downgraded():
    r = {x["id"]: x for x in ranked()}
    assert r["CVE-3"]["usage"] == "undetermined" and r["CVE-3"]["score"] == 3.2  # 4 * 0.8 * 1.0


def run_llm(llm, items=None):
    items = items or ranked()
    return asyncio.run(rank_with_llm(items, llm))


def test_valid_llm_answer_reorders_and_explains():
    async def llm(bundle):
        return {"rankings": [{"key": "CVE-2:b", "reason": "internet facing parser"}]}

    result, how = run_llm(llm)
    assert how == "llm"
    assert result[0]["key"] == "CVE-2:b" and result[0]["reason"] == "internet facing parser"
    assert len(result) == 3  # findings the LLM did not mention are kept


@pytest.mark.parametrize("answer", [
    {"rankings": [{"key": "CVE-999:x", "reason": "invented"}]},                              # unknown finding
    {"rankings": [{"key": "CVE-1:a", "reason": "x"}, {"key": "CVE-1:a", "reason": "y"}]},    # duplicate
    {"rankings": [{"key": "CVE-1:a", "reason": "token=AKIAABCDEFGHIJKLMNOP"}]},              # secret in output
    {"wrong": "shape"},                                                                      # schema
])
def test_invalid_llm_answer_is_retried_once_then_falls_back(answer):
    calls = []

    async def llm(bundle):
        calls.append(1)
        return answer

    result, how = run_llm(llm)
    assert how == "deterministic" and result == ranked()
    assert len(calls) == 2


def test_unavailable_llm_falls_back_without_retry():
    calls = []

    async def llm(bundle):
        calls.append(1)
        raise ConnectionError("down")

    assert run_llm(llm)[1] == "deterministic"
    assert len(calls) == 1


def test_no_llm_means_deterministic():
    assert run_llm(None)[1] == "deterministic"


def test_validate_rejects_unknown_key():
    with pytest.raises(ValueError):
        validate_llm_output({"rankings": [{"key": "nope", "reason": "x"}]}, {"CVE-1:a"})
