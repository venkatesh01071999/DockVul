import pytest

from gateway.config import ConfigError, Settings

SECRETS = {"GATEWAY_TOKEN": "g" * 16, "WORKER_TOKEN": "w" * 16, "APPROVAL_SECRET": "s" * 16}


def test_from_env_uses_defaults_and_overrides():
    s = Settings.from_env({**SECRETS, "SLIM_CONCURRENCY": "2", "TRIVY_WORKER_URL": "http://t:9/",
                           "ALLOWED_HOSTS": "gw:*, localhost:*"})
    assert s.concurrency["slim"] == 2 and s.concurrency["trivy"] == 4      # override vs default
    assert s.worker_urls["trivy"] == "http://t:9"                          # trailing slash stripped
    assert s.allowed_hosts == ("gw:*", "localhost:*")
    assert s.approval_secret == b"s" * 16


@pytest.mark.parametrize("env", [
    {},                                              # nothing set
    {**SECRETS, "WORKER_TOKEN": "short"},            # secret too short
])
def test_missing_or_short_secrets_refuse_to_start(env):
    with pytest.raises(ConfigError, match="at least 16"):
        Settings.from_env(env)


@pytest.mark.parametrize("name,value", [("GATEWAY_PORT", "abc"), ("TRIVY_CONCURRENCY", "0")])
def test_bad_numbers_are_rejected(name, value):
    with pytest.raises(ConfigError, match=name):
        Settings.from_env({**SECRETS, name: value})
