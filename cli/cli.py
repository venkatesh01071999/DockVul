import argparse
from pathlib import Path

def validate(args: argparse.Namespace, parser: argparse.ArgumentParser):
    """
    Check that the inputs are consistent with each other (e.g. --commit needs
    a GitHub source) and exit with a usage error if they are not.
    """

    is_github = bool(args.source) and args.source.startswith(("https://github.com/", "git@github.com:"))
    is_local = bool(args.source) and Path(args.source).is_dir()

    if args.image.endswith((".tar", ".tar.gz", ".tgz")) and not Path(args.image).is_file():
        parser.error(f"Image tarball not found: {args.image}")
    if args.source and not (is_github or is_local):
        parser.error("--source must be a GitHub URL or an existing local directory")
    if args.commit and not is_github:
        parser.error("--commit requires a GitHub --source")
    if (args.dockerfile or args.compose_file or args.source_subdir) and not args.source:
        parser.error("--dockerfile, --compose-file and --source-subdir require --source")
    if args.compose_service and not args.compose_file:
        parser.error("--compose-service requires --compose-file")


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


def parse_args():
    """
    Build the parser, reads the command line, validates it and return the parsed arguments. 
    Omitted optional inputs stay None.
    """
    parser = build_parser()
    args = parser.parse_args()
    validate(args, parser)
    
    return args


if __name__ == "__main__":
    # pragma: no cover
    args = parse_args()
