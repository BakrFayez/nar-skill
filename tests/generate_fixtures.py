#!/usr/bin/env python3
"""Generate the public synthetic fixture set + manifest.

Usage:
    python3 tests/generate_fixtures.py --out DIR

Writes every synthetic fixture built by
tests/synthetic_fixtures.py into DIR, plus the
expected-output manifest as DIR/expected_outputs.json.
The manifest records the builders' intended facts (see
the design note in tests/synthetic_fixtures.py); the
committed copy at tests/expected_outputs.json is this
same output, and the regression tests fail if the two
drift apart.

Runs on a bare python3 (stdlib only), from a clean clone,
with no private fixture corpus. Part of NAR (Nirous
Android Reversing).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import synthetic_fixtures  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Write the synthetic fixtures and the "
                    "expected-output manifest into a "
                    "directory.")
    parser.add_argument("--out", required=True,
                        metavar="DIR",
                        help="directory to write fixtures "
                             "+ expected_outputs.json into")
    args = parser.parse_args(argv)
    manifest = synthetic_fixtures.generate(args.out)
    for fixture_id, entry in manifest["fixtures"].items():
        print(f"{fixture_id}: {', '.join(entry['files'])}")
    print(f"manifest: "
          f"{Path(args.out) / 'expected_outputs.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
