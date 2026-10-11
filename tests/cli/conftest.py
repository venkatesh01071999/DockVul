import pytest

from cli.cli import build_parser, parse_args

"""

A set of pytest fixtures which are reusable and define the setup and teardown of environments for testing the CLI.

"""
@pytest.fixture
def parser():
    return build_parser()

# with monkeypatch we can set various attributes in a convenient way, e.g. sys.argv for testing the CLI parser.
@pytest.fixture
def run_cli(monkeypatch):
    """Run parse_args() with the given argv (excluding the program name)."""

    def _run(*argv):
        monkeypatch.setattr("sys.argv", ["cli.py", *argv])
        return parse_args()

    return _run


@pytest.fixture
def source_dir(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    return d
