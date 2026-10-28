"""
Append-only audit log

Callers pass a small summary of the arguments (image reference, digest, flags), never whole
payloads and never worker output.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


class AuditLog:
    def __init__(self, path: Optional[Path] = None, sink: Optional[Callable[[str], None]] = None) -> None:
        self._path = path
        self._sink = sink

    def record(self, **fields: Any) -> None:
        line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **fields}, default=str, sort_keys=True)
        if self._sink:
            self._sink(line)
        elif self._path:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        else: # pragma: no cover
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
