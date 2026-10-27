from gateway.masking import mask


def test_env_assignment_with_secret_name_is_masked():
    masked, count = mask({"Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2"]})
    assert masked == {"Env": ["PATH=/usr/bin", "DB_PASSWORD=<REDACTED:env_secret>"]}
    assert count == 1


def test_known_token_format_gets_a_typed_placeholder():
    masked, count = mask("deploy with AKIAABCDEFGHIJKLMNOP now")
    assert masked == "deploy with <REDACTED:aws_access_key> now"
    assert count == 1


def test_value_under_secret_key_is_masked():
    masked, _ = mask({"api_key": "abc123", "name": "web"})
    assert masked == {"api_key": "<REDACTED:secret>", "name": "web"}


def test_trivy_secret_finding_hides_match_and_code():
    finding = {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Match": "key=AKIAABCDEFGHIJKLMNOP",
               "Code": {"Lines": [{"Content": "key=AKIAABCDEFGHIJKLMNOP"}]}}
    masked, _ = mask({"Secrets": [finding]})
    assert masked["Secrets"][0]["Match"] == "<REDACTED:secret_finding>"
    assert masked["Secrets"][0]["Code"] == "<REDACTED:secret_finding>"
    assert masked["Secrets"][0]["RuleID"] == "aws-access-key-id"  # the finding itself stays visible


def test_ordinary_data_is_left_alone_and_input_is_not_modified():
    data = {"PkgName": "openssl", "Severity": "HIGH", "Count": 3, "Result": "PASS", "Cmd": "bypass=1"}
    masked, count = mask(data)
    assert masked == data
    assert count == 0
    assert masked is not data
