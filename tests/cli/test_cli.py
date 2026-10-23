import pytest

from common.schemas import (
    GithubSource, LocalSource, RegistryImage, ScanRequest, TarballImage,
)

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
        assert run_cli("--image", "nginx:latest").image == RegistryImage(ref="nginx:latest")

    @pytest.mark.parametrize("name", ["img.tar", "img.tar.gz", "img.tgz"])
    def test_existing_tarball_accepted(self, run_cli, tmp_path, name):
        tarball = tmp_path / name
        tarball.write_bytes(b"")
        assert run_cli("--image", str(tarball)).image == TarballImage(name=name)

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
        assert run_cli("--image", "x", "--source", url).source == GithubSource(repo="owner/repo")

    def test_local_directory_accepted(self, run_cli, source_dir):
        assert run_cli("--image", "x", "--source", str(source_dir)).source == LocalSource()

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
        assert run_cli("--image", "x", "--source", "").source == None


class TestCommitValidation:
    def test_commit_with_github_source_accepted(self, run_cli):
        args = run_cli("--image", "x", "--source", GH_HTTPS, "--commit", "abc1234")
        assert args.source.commit == GithubSource(repo="owner/repo", commit="abc1234").commit

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
    def test_accepted_with_github_source(self, run_cli, flag, value):
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


class TestLocalSourceLooksLikeProject:
    @pytest.mark.parametrize("marker", [
        "Dockerfile", "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml",
    ])
    def test_marker_file_accepted(self, run_cli, empty_dir, marker):
        (empty_dir / marker).write_text("x")
        assert run_cli("--image", "x", "--source", str(empty_dir)).source == LocalSource()

    def test_empty_directory_rejected(self, run_cli, empty_dir, capsys):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(empty_dir))
        assert_usage_error(e, capsys, "does not look like a project")

    def test_directory_with_unrelated_files_rejected(self, run_cli, empty_dir, capsys):
        (empty_dir / "notes.txt").write_text("x")
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(empty_dir))
        assert_usage_error(e, capsys, "does not look like a project")

    def test_marker_that_is_a_directory_rejected(self, run_cli, empty_dir, capsys):
        (empty_dir / "Dockerfile").mkdir()
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(empty_dir))
        assert_usage_error(e, capsys, "does not look like a project")

    @pytest.mark.parametrize("flag,rel", [("--dockerfile", "build/Dockerfile"), ("--compose-file", "deploy/dc.yml")])
    def test_explicit_file_inside_source_counts_as_marker(self, run_cli, empty_dir, flag, rel):
        (empty_dir / rel).parent.mkdir()
        (empty_dir / rel).write_text("x")
        run_cli("--image", "x", "--source", str(empty_dir), flag, rel)

    @pytest.mark.parametrize("flag", ["--dockerfile", "--compose-file"])
    def test_missing_explicit_file_rejected(self, run_cli, source_dir, capsys, flag):
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(source_dir), flag, "nope.txt")
        assert_usage_error(e, capsys, f"{flag} not found inside --source")

    def test_symlink_escaping_source_rejected(self, run_cli, empty_dir, tmp_path, capsys):
        outside = tmp_path / "outside"
        outside.write_text("FROM scratch")
        try:
            (empty_dir / "Dockerfile").symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("cannot create symlinks on this platform")
        with pytest.raises(SystemExit) as e:
            run_cli("--image", "x", "--source", str(empty_dir))
        assert_usage_error(e, capsys, "does not look like a project")


class TestToScanRequest:
    def test_registry_image(self, convert):
        assert convert("--image", "nginx:latest").image == RegistryImage(ref="nginx:latest")

    @pytest.mark.parametrize("name", ["img.tar", "img.tar.gz", "img.tgz"])
    def test_tarball_keeps_only_file_name(self, convert, tmp_path, name):
        (tmp_path / name).write_bytes(b"")
        req = convert("--image", str(tmp_path / name))
        assert req.image == TarballImage(name=name)

    def test_no_source(self, convert):
        assert convert("--image", "x").source is None

    def test_empty_source_is_absent(self, convert):
        assert convert("--image", "x", "--source", "").source is None

    @pytest.mark.parametrize("url", [
        GH_HTTPS, GH_HTTPS + ".git", GH_HTTPS + "/", GH_SSH,
    ])
    def test_github_url_becomes_owner_repo(self, convert, url):
        assert convert("--image", "x", "--source", url).source == GithubSource(repo="owner/repo")

    def test_commit_moves_onto_github_source_lowercased(self, convert):
        req = convert("--image", "x", "--source", GH_HTTPS, "--commit", "ABC1234")
        assert req.source == GithubSource(repo="owner/repo", commit="abc1234")

    def test_local_source_is_a_marker_without_the_host_path(self, convert, source_dir):
        req = convert("--image", "x", "--source", str(source_dir))
        assert req.source == LocalSource()
        assert str(source_dir) not in req.model_dump_json()

    def test_other_fields_pass_through_normalized(self, convert):
        req = convert("--image", "x", "--source", GH_HTTPS, "--dockerfile", "build\\Dockerfile",
                      "--compose-file", "./dc.yml", "--compose-service", "web", "--source-subdir", "app")
        assert (req.dockerfile, req.compose_file, req.compose_service, req.source_subdir) == (
            "build/Dockerfile", "dc.yml", "web", "app")

    def test_round_trips_through_json(self, convert):
        req = convert("--image", "x", "--source", GH_HTTPS, "--commit", "abc1234", "--compose-file", "dc.yml")
        assert ScanRequest.model_validate_json(req.model_dump_json()) == req

    @pytest.mark.parametrize("argv,message", [
        (["--image=-flag"], "invalid input: ref: invalid registry image reference"),
        (["--image", "x", "--source", "https://github.com/owner"], "--source: not a GitHub URL"),
        (["--image", "x", "--source", GH_HTTPS, "--commit", "main"], "commit must be a 7-40 character hex SHA"),
        (["--image", "x", "--source", GH_HTTPS, "--dockerfile", "../x"], "invalid input: dockerfile"),
        (["--image", "x", "--source", GH_HTTPS, "--compose-file", "dc.yml", "--compose-service=-bad"],
         "invalid compose service name"),
    ])
    def test_schema_rejection_is_a_usage_error(self, convert, capsys, argv, message):
        with pytest.raises(SystemExit) as e:
            convert(*argv)
        assert_usage_error(e, capsys, message)

    def test_tarball_name_rejected_by_schema(self, convert, tmp_path, capsys):
        (tmp_path / "-img.tar").write_bytes(b"")
        with pytest.raises(SystemExit) as e:
            convert("--image", str(tmp_path / "-img.tar"))
        assert_usage_error(e, capsys, "invalid input: name: tarball must be a file name")
