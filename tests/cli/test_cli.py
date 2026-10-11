import pytest

GH_HTTPS = "https://github.com/owner/repo"
GH_SSH = "git@github.com:owner/repo.git"


def assert_usage_error(excinfo, capsys, message):
    assert excinfo.value.code == 2
    assert message in capsys.readouterr().err


class TestBuildParser:
    # parser from conftest.py fixture
    def test_image_is_required(self, parser, capsys):
        with pytest.raises(SystemExit) as e:
            parser.parse_args([])
        assert_usage_error(e, capsys, "--image")

    def test_optional_args_default_to_none(self, parser):
        args = parser.parse_args(["--image", "nginx:latest"])
        assert args.image == "nginx:latest"
        for name in ("source", "commit", "dockerfile", "compose_file", "compose_service", "source_subdir"):
            assert getattr(args, name) is None

    def test_all_args_parsed(self, parser):
        args = parser.parse_args([
            "--image", "img.tar", "--source", GH_HTTPS, "--commit", "abc123",
            "--dockerfile", "Dockerfile", "--compose-file", "dc.yml",
            "--compose-service", "web", "--source-subdir", "app",
        ])
        assert vars(args) == {
            "image": "img.tar", "source": GH_HTTPS, "commit": "abc123",
            "dockerfile": "Dockerfile", "compose_file": "dc.yml",
            "compose_service": "web", "source_subdir": "app",
        }

    def test_unknown_arg_rejected(self, parser, capsys):
        with pytest.raises(SystemExit) as e:
            parser.parse_args(["--image", "x", "--bogus", "1"])
        assert_usage_error(e, capsys, "unrecognized arguments")


class TestImageValidation:
    def test_registry_ref_accepted(self, run_cli):
        assert run_cli("--image", "nginx:latest").image == "nginx:latest"

    @pytest.mark.parametrize("name", ["img.tar", "img.tar.gz", "img.tgz"])
    def test_existing_tarball_accepted(self, run_cli, tmp_path, name):
        tarball = tmp_path / name
        tarball.write_bytes(b"")
        assert run_cli("--image", str(tarball)).image == str(tarball)

    @pytest.mark.parametrize("name", ["missing.tar", "missing.tar.gz", "missing.tgz"])
    def test_missing_tarball_rejected(self, run_cli, tmp_path, capsys, name):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", str(tmp_path / name))
        assert_usage_error(e, capsys, "Image tarball not found")

    def test_directory_named_like_tarball(self, run_cli, tmp_path, capsys):
        d = tmp_path / "dir.tar"
        d.mkdir()
        with pytest.raises(SystemExit) as e:
            run_cli("--image", str(d))
        assert_usage_error(e, capsys, "Image tarball not found")


class TestSourceValidation:
    @pytest.mark.parametrize("url", [GH_HTTPS, GH_SSH])
    def test_github_source_accepted(self, run_cli, url):
        assert run_cli("--image", "x", "--source", url).source == url

    def test_local_directory_accepted(self, run_cli, source_dir):
        assert run_cli("--image", "x", "--source", str(source_dir)).source == str(source_dir)

    @pytest.mark.parametrize("source", [
        "https://gitlab.com/owner/repo",
        "http://github.com/owner/repo",
        "not-a-real-dir",
    ])
    def test_invalid_source_rejected(self, run_cli, capsys, source):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", source)
        assert_usage_error(e, capsys, "--source must be a GitHub URL or an existing local directory")

    def test_file_as_source_rejected(self, run_cli, tmp_path, capsys):
        f = tmp_path / "file.txt"
        f.write_text("x")
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(f))
        assert_usage_error(e, capsys, "--source must be")

    def test_empty_source_treated_as_absent(self, run_cli):
        assert run_cli("--image", "x", "--source", "").source == ""


class TestCommitValidation:
    def test_commit_with_github_source_accepted(self, run_cli):
        args = run_cli("--image", "x", "--source", GH_HTTPS, "--commit", "abc")
        assert args.commit == "abc"

    def test_commit_with_local_source_rejected(self, run_cli, source_dir, capsys):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(source_dir), "--commit", "abc")
        assert_usage_error(e, capsys, "--commit requires a GitHub --source")

    def test_commit_without_source_rejected(self, run_cli, capsys):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--commit", "abc")
        assert_usage_error(e, capsys, "--commit requires a GitHub --source")


class TestSourceDependentOptions:
    @pytest.mark.parametrize("flag,value", [
        ("--dockerfile", "Dockerfile"),
        ("--compose-file", "dc.yml"),
        ("--source-subdir", "app"),
    ])
    def test_require_source(self, run_cli, capsys, flag, value):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", flag, value)
        assert_usage_error(e, capsys, "require --source")

    @pytest.mark.parametrize("flag,value", [
        ("--dockerfile", "Dockerfile"),
        ("--compose-file", "dc.yml"),
        ("--source-subdir", "app"),
    ])
    def test_accepted_with_source(self, run_cli, source_dir, flag, value):
        args = run_cli("--image", "x", "--source", str(source_dir), flag, value)
        assert getattr(args, flag.lstrip("-").replace("-", "_")) == value

    @pytest.mark.parametrize("flag,value", [
            ("--dockerfile", "Dockerfile"),
            ("--compose-file", "dc.yml"),
            ("--source-subdir", "app"),
    ])
    def test_accepted_with_source(self, run_cli, source_dir, flag, value):
        args = run_cli("--image", "x", "--source", GH_HTTPS, flag, value)
        assert getattr(args, flag.lstrip("-").replace("-", "_")) == value


class TestComposeService:
    def test_requires_compose_file(self, run_cli, source_dir, capsys):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(source_dir), "--compose-service", "web")
        assert_usage_error(e, capsys, "--compose-service requires --compose-file")

    def test_accepted_with_compose_file(self, run_cli, source_dir):
        args = run_cli("--image", "x", "--source", str(source_dir),
                       "--compose-file", "dc.yml", "--compose-service", "web")
        assert args.compose_service == "web"
