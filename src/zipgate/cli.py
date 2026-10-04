"""zipgate CLI: audit wheels/zips for malformed ZIP64 structures."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checker import Verdict, audit_zip


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="zipgate",
        description="Audit zip/wheel files for malformed ZIP64 extra fields.",
    )
    p.add_argument("files", nargs="+", help="zip or wheel files to audit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    worst = 0
    for path in args.files:
        result = audit_zip(path)
        print(f"{result.verdict.value}: {path}")
        for f in result.findings:
            print(f"  [{f.rule}] {f.entry}: {f.detail}")
        if result.verdict is Verdict.INVALID:
            worst = max(worst, 1)
        elif result.verdict is Verdict.UNREADABLE:
            worst = max(worst, 2)
    return worst


if __name__ == "__main__":
    sys.exit(main())
