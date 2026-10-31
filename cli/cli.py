import argparse
import asyncio
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from common.schemas import (
    GithubSource,
    LocalSource,
    RegistryImage,
    ScanRequest,
    TarballImage,
    parse_github_url,
)

from orchestrator.config import ConfigError, Settings
from orchestrator.gateway_client import GatewayClient
from orchestrator.graph import run_scan
from orchestrator.report import exit_code, write_report

TARBALL_SUFFIXES = (".tar", ".tar.gz", ".tgz")
GITHUB_PREFIXES = ("https://github.com/", "git@github.com:")
PROJECT_MARKERS = ("Dockerfile", "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


def file_inside(root: Path, rel: str) -> bool:
    """True if `rel` is an existing file whose real path (symlinks followed) is inside `root`."""
    target = (root / rel).resolve()
    return target.is_file() and target.is_relative_to(root)


def check_local_source(args: argparse.Namespace, parser: argparse.ArgumentParser):
    """
    A local --source is mounted into the scanner, so it must look like a project rather than
    being any directory (home folder, drive root ...): it has to contain a Dockerfile or compose
    file, or --dockerfile / --compose-file must point at a real file inside it.
    """
    root = Path(args.source).resolve()

    for flag, value in (("--dockerfile", args.dockerfile), ("--compose-file", args.compose_file)):
        if value and not file_inside(root, value):
            parser.error(f"{flag} not found inside --source: {value}")

    if not (args.dockerfile or args.compose_file or any(file_inside(root, m) for m in PROJECT_MARKERS)):
        parser.error(
            "--source directory does not look like a project (no Dockerfile or compose file found); "
            "use --dockerfile or --compose-file to point at one"
        )


def validate(args: argparse.Namespace, parser: argparse.ArgumentParser):
    """
    Check that the inputs are consistent with each other (e.g. --commit needs
    a GitHub source) and exit with a usage error if they are not.
    """

    is_github = bool(args.source) and args.source.startswith(GITHUB_PREFIXES)
    is_local = bool(args.source) and Path(args.source).is_dir()

    if args.image.endswith(TARBALL_SUFFIXES) and not Path(args.image).is_file():
        parser.error(f"Image tarball not found: {args.image}")
    if args.source and not (is_github or is_local):
        parser.error("--source must be a GitHub URL or an existing local directory")
    if args.commit and not is_github:
        parser.error("--commit requires a GitHub --source")
    if (args.dockerfile or args.compose_file or args.source_subdir) and not args.source:
        parser.error("--dockerfile, --compose-file and --source-subdir require --source")
    if args.compose_service and not args.compose_file:
        parser.error("--compose-service requires --compose-file")
    if is_local:
        check_local_source(args, parser)


def to_scan_request(args: argparse.Namespace, parser: argparse.ArgumentParser) -> ScanRequest:
    """
    Convert the validated CLI arguments into the normalized ScanRequest that travels to LangGraph,
    the MCP gateway and the workers. Host-specific details are dropped on purpose: a tarball
    becomes its bare file name, a local source becomes a marker (the directory is mounted at a
    fixed path), a GitHub URL becomes "owner/repo" and the commit moves onto the GitHub source.
    Exits with a usage error if the schema rejects a value.
    """
    try:
        if args.image.endswith(TARBALL_SUFFIXES):
            image = TarballImage(name=Path(args.image).name)
        else:
            image = RegistryImage(ref=args.image)

        source = None
        if args.source:
            if args.source.startswith(GITHUB_PREFIXES):
                owner, repo = parse_github_url(args.source)
                source = GithubSource(repo=f"{owner}/{repo}", commit=args.commit)
            else:
                source = LocalSource() # A marker for the local source. Host wrapper mounts it at a fixed path, so the workers can find it.

        return ScanRequest(
            image=image,
            source=source,
            dockerfile=args.dockerfile,
            compose_file=args.compose_file,
            compose_service=args.compose_service,
            source_subdir=args.source_subdir,
        )
    except ValidationError as e:
        details = "; ".join(
            ": ".join(filter(None, (".".join(str(p) for p in err["loc"]), err["msg"].removeprefix("Value error, "))))
            for err in e.errors()
        )
        parser.error(f"invalid input: {details}")
    except ValueError as e:  # parse_github_url, e.g. https://github.com/owner (no repo)
        parser.error(f"--source: {e}")


def build_parser():
    """
    Define the command-line arguments: 
    1) image
    2) optional source,
    3) optional commit
    4) optional Dockerfile, 
    5) optional compose 
    6) optional subdirectory settings.
    """

    p = argparse.ArgumentParser(description="DockVul: A Docker Image Vulnerability Scanner")
    p.add_argument("--image", help="Registry ref (e.g. nginx:latest) or local tarball (.tar)", required=True)
    p.add_argument("--source", help="Optional: GitHub repo URL or local directory (default: code inside the image)", required=False)
    p.add_argument("--commit", help="Optional: Commit SHA (GitHub source only)", required=False)
    p.add_argument("--dockerfile", help="Optional: Dockerfile path within the source (default: reconstructed from image history using docker inspect etc.)", required=False)
    p.add_argument("--compose-file", help="Optional: Compose file path within the source (default: runtime settings not assessed if not provided)", required=False)
    p.add_argument("--compose-service", help="Optional: Compose service name (needed if the file has several services)", required=False)
    p.add_argument("--source-subdir", help="Optional: Subdirectory for source code check (default: Dockerfile's build context)", required=False)
    return p

def parse_request() -> ScanRequest:
    """Parse and validate the command line and return the normalized ScanRequest."""
    parser = build_parser()
    args = parser.parse_args()
    validate(args, parser)
    return to_scan_request(args, parser)


async def ask_human(info: dict) -> bool:
    """
    Ask a person whether the sandbox checks may run. Anything but an explicit "y" is a no, 
    so the privileged sandbox never starts unattended.
    """
    if not sys.stdin.isatty():
        return False
    print("\nSandbox checks need your approval.")
    print(f"  image digest : {info['image_digest']}")
    print(f"  WARNING      : {info['warning']}")
    answer = await asyncio.to_thread(input, "Run the sandbox checks? [y/N] ")
    return answer.strip().lower() == "y"


async def scan(request: ScanRequest) -> int:  # pragma: no cover
    """Run the LangGraph orchestration for the request, write the report and return the exit code."""

    try:
        settings = Settings.from_env()
    except ConfigError as e:
        sys.exit(f"configuration error: {e}")
    gateway = GatewayClient(settings.gateway_url, settings.gateway_token, settings.call_timeout)
    report = await run_scan(request, gateway, settings, approve=ask_human)
    path = write_report(report, Path(os.environ.get("DOCKVUL_OUTPUT_DIR", "output")))
    print(f"report written to {path} ({report['status']}, {len(report['findings'])} findings)")
    return exit_code(report)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(asyncio.run(scan(parse_request())))
