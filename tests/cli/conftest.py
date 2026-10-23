import pytest

from cli.cli import build_parser, to_scan_request, validate, parse_request

"""

A set of pytest fixtures which are reusable and define the setup and teardown of environments for testing the CLI.

"""
@pytest.fixture
def parser():
    return build_parser()

# with monkeypatch we can set various attributes in a convenient way, e.g. sys.argv for testing the CLI parser.
@pytest.fixture
def run_cli(monkeypatch):
    """Run parse_request() with the given argv (excluding the program name)."""

    def _run(*argv):
        monkeypatch.setattr("sys.argv", ["cli.py", *argv])
        return parse_request()

    return _run


@pytest.fixture
def source_dir(tmp_path):
    """A directory that looks like a project (has a Dockerfile and a compose file)."""
    d = tmp_path / "src"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM scratch\n")
    (d / "dc.yml").write_text("services: {}\n")
    return d


@pytest.fixture
def empty_dir(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    return d

@pytest.fixture
def convert(parser):
    def _convert(*argv):
        args = parser.parse_args(list(argv))
        validate(args, parser)
        return to_scan_request(args, parser)
    return _convert