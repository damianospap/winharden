#!/usr/bin/env python3
"""Keeps tests/vectors/audit-lint.json complete: every audit command used by a manifest must be a vector.

The PowerShell lint (engine/Policy.ps1) is tested against the same vectors as the Python lint, so a manifest command that
is missing here would only ever be linted by one of the two implementations.

    python tools/sync_lint_vectors.py          add the missing commands (each one must pass the lint)
    python tools/sync_lint_vectors.py --check  exit 1 when the file is out of date, change nothing
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import validate_manifests as V  # noqa: E402

VECTORS = ROOT / "tests" / "vectors" / "audit-lint.json"
MARK = "manifest command"


def manifest_commands() -> list[str]:
    seen: dict[str, None] = {}
    for path in sorted((ROOT / "manifests").glob("*.json")):
        for entry in json.loads(path.read_text(encoding="utf-8"))["entries"]:
            for check in entry["audit"].get("checks", []):
                seen.setdefault(check["command"], None)
    return list(seen)


def main(argv: list[str]) -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    known = {v["command"] for v in vectors}
    missing = [c for c in manifest_commands() if c not in known]
    refused = [(c, V.lint_audit(c)) for c in missing if V.lint_audit(c)]
    for command, why in refused:
        print(f"REFUSED by the lint: {command}\n    {'; '.join(why)}")
    if refused:
        return 1
    if "--check" in argv:
        if missing:
            print(f"{len(missing)} manifest audit commands are not in {VECTORS.name}; run tools/sync_lint_vectors.py")
            return 1
        print(f"OK: {VECTORS.name} is current")
        return 0
    last = max((i for i, v in enumerate(vectors) if v["name"] == MARK), default=len(vectors) - 1)
    vectors[last + 1:last + 1] = [{"name": MARK, "command": c, "ok": True} for c in missing]
    VECTORS.write_text(json.dumps(vectors, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"added {len(missing)} commands; {len(vectors)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
