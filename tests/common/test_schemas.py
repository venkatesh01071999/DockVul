import pytest
from pydantic import ValidationError

from common.schemas import (
    GithubSource,
    LocalSource,
    RegistryImage,
    ScanRequest,
    TarballImage,
    parse_github_url,
    safe_relpath,
    validate_run_id,
)

REG = {"kind": "registry", "ref": "nginx:latest"}
GH = {"kind": "github", "repo": "owner/repo"}


def make(**kwargs):
    return ScanRequest.model_validate({"image": REG, **kwargs})


class TestRegistryImage:
    @pytest.mark.parametrize("ref", [
        "nginx", "nginx:latest", "library/nginx:1.25",
        "localhost:5000/team/app:v1", "ghcr.io/o/r@sha256:" + "a" * 64,
    ])
    def test_valid(self, ref):
        assert RegistryImage(ref=ref).ref == ref

    @pytest.mark.parametrize("ref", ["", "-flag", "--config=evil", "a b", "a;b", "a$(x)", "a\nb", "x" * 300])
    def test_invalid(self, ref):
        with pytest.raises(ValidationError):
            RegistryImage(ref=ref)


class TestTarballImage:
    @pytest.mark.parametrize("name", ["img.tar", "my-app_1.2.tar.gz", "img.tgz"])
    def test_valid(self, name):
        assert TarballImage(name=name).name == name

    @pytest.mark.parametrize("name", [
        "img", "img.zip", "-img.tar", "dir/img.tar", "..\\img.tar", "/abs/img.tar", "C:\\img.tar", ".tar",
    ])
    def test_invalid(self, name):
        with pytest.raises(ValidationError):
            TarballImage(name=name)


class TestGithubSource:
    def test_valid(self):
        s = GithubSource(repo="owner/repo.js", commit="abc1234")
        assert (s.repo, s.commit) == ("owner/repo.js", "abc1234")

    def test_commit_optional(self):
        assert GithubSource(repo="o/r").commit is None

    def test_commit_lowercased(self):
        assert GithubSource(repo="o/r", commit="ABCDEF1").commit == "abcdef1"

    @pytest.mark.parametrize("repo", ["", "owner", "a/b/c", "../x", "x/..", "./x", "o/r r", "o/r;x", "/o/r"])
    def test_invalid_repo(self, repo):
        with pytest.raises(ValidationError):
            GithubSource(repo=repo)

    @pytest.mark.parametrize("commit", ["", "abc12", "g" * 7, "a" * 41, "abc123; rm -rf", "main"])
    def test_invalid_commit(self, commit):
        with pytest.raises(ValidationError):
            GithubSource(repo="o/r", commit=commit)


class TestParseGithubUrl:
    @pytest.mark.parametrize("url", [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://github.com/owner/repo/",
        "git@github.com:owner/repo.git",
    ])
    def test_valid(self, url):
        assert parse_github_url(url) == ("owner", "repo")

    @pytest.mark.parametrize("url", [
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/tree/main",
        "https://github.com.evil.com/owner/repo",
        "owner/repo",
    ])
    def test_invalid(self, url):
        with pytest.raises(ValueError):
            parse_github_url(url)


class TestSafeRelpath:
    @pytest.mark.parametrize("raw,expected", [
        ("Dockerfile", "Dockerfile"),
        ("build/Dockerfile", "build/Dockerfile"),
        ("build\\Dockerfile", "build/Dockerfile"),   # Windows separators normalized
        ("./app", "app"),
        ("my app/src", "my app/src"),
    ])
    def test_valid(self, raw, expected):
        assert safe_relpath(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", "../x", "a/../../x", "a/..", "/etc/passwd", "\\\\server\\share",
        "C:\\x", "C:/x", "-rf", "a\x00b", "x" * 300,
    ])
    def test_invalid(self, raw):
        with pytest.raises(ValueError):
            safe_relpath(raw)


class TestValidateRunId:
    def test_valid(self):
        assert validate_run_id("run_2026-10-23_ab") == "run_2026-10-23_ab"

    @pytest.mark.parametrize("v", ["short", "has space 123", "../../etc/passwd", "x" * 65, "a/b/c/d/e/f"])
    def test_invalid(self, v):
        with pytest.raises(ValueError):
            validate_run_id(v)


class TestScanRequest:
    def test_minimal(self):
        r = make()
        assert r.image == RegistryImage(ref="nginx:latest")
        for name in ("source", "dockerfile", "compose_file", "compose_service", "source_subdir"):
            assert getattr(r, name) is None

    def test_full_github(self):
        r = make(source={**GH, "commit": "abc1234"}, dockerfile="build\\Dockerfile",
                 compose_file="dc.yml", compose_service="web", source_subdir="app")
        assert r.source == GithubSource(repo="owner/repo", commit="abc1234")
        assert r.dockerfile == "build/Dockerfile"

    def test_tarball_and_local_source(self):
        r = ScanRequest(image=TarballImage(name="img.tar"), source=LocalSource(), dockerfile="Dockerfile")
        assert r.source.kind == "local"

    def test_image_kind_is_discriminated(self):
        r = ScanRequest.model_validate({"image": {"kind": "tarball", "name": "img.tar"}})
        assert isinstance(r.image, TarballImage)

    def test_unknown_image_kind_rejected(self):
        with pytest.raises(ValidationError):
            ScanRequest.model_validate({"image": {"kind": "ftp", "ref": "x"}})

    def test_image_required(self):
        with pytest.raises(ValidationError):
            ScanRequest.model_validate({})

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError, match="extra"):
            make(entrypoint="sh -c evil")

    def test_unknown_field_inside_nested_model_rejected(self):
        with pytest.raises(ValidationError):
            make(source={**GH, "token": "ghp_x"})

    def test_empty_strings_treated_as_absent(self):
        r = make(dockerfile="", compose_file="", compose_service="", source_subdir="")
        assert r.dockerfile is r.compose_file is r.compose_service is r.source_subdir is None

    def test_frozen(self):
        with pytest.raises(ValidationError):
            make().dockerfile = "x"

    @pytest.mark.parametrize("field", ["dockerfile", "compose_file", "source_subdir"])
    @pytest.mark.parametrize("bad", ["../x", "/etc/passwd", "C:\\x", "-rf"])
    def test_bad_paths_rejected(self, field, bad):
        with pytest.raises(ValidationError):
            make(source=GH, **{field: bad})

    @pytest.mark.parametrize("field", ["dockerfile", "compose_file", "source_subdir"])
    def test_path_options_require_source(self, field):
        with pytest.raises(ValidationError, match="require a source"):
            make(**{field: "x"})

    def test_compose_service_requires_compose_file(self):
        with pytest.raises(ValidationError, match="compose_service requires compose_file"):
            make(source=GH, compose_service="web")

    @pytest.mark.parametrize("name", ["web", "web-1", "my_svc.v2"])
    def test_valid_service_names(self, name):
        assert make(source=GH, compose_file="dc.yml", compose_service=name).compose_service == name

    @pytest.mark.parametrize("name", ["-web", "we b", "web;ls", "a" * 64])
    def test_invalid_service_names(self, name):
        with pytest.raises(ValidationError):
            make(source=GH, compose_file="dc.yml", compose_service=name)

    def test_json_round_trip(self):
        r = make(source={**GH, "commit": "abc1234"}, compose_file="dc.yml")
        assert ScanRequest.model_validate(r.model_dump(mode="json")) == r
        assert ScanRequest.model_validate_json(r.model_dump_json()) == r
