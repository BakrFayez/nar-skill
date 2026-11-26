#!/usr/bin/env python3
"""nar-input.py: universal input identification, validation,
duplicate detection, and safe extraction (brief section 3.1).

    python3 nar-input.py identify target [--json]
    python3 nar-input.py validate target [--json]
    python3 nar-input.py extract target --out DIR [--json]
    python3 nar-input.py duplicates FILE... [--json]
    python3 nar-input.py duplicates --dir DIR [--json]

Identification is by signature + internal structure (narlib.
formats), never by filename alone; a name/content mismatch is
reported. Extraction goes through the safe-archive layer:
traversal, symlink, and bomb entries are refused and listed,
never silently skipped. Inputs are untrusted and are never
executed.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import formats, safearchive  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402


def cmd_identify(args):
    verdict = formats.identify(args.target)
    verdict["validation_notes"] = formats.validate_structure(
        args.target, verdict)
    return verdict


def cmd_validate(args):
    verdict = formats.identify(args.target)
    notes = formats.validate_structure(args.target, verdict)
    if verdict["format"] == "unknown":
        # Nothing was identified, so nothing could be
        # validated: a vacuous pass would assert validity
        # for random bytes, an empty file, or junk under a
        # container name (certification B-02).
        notes.insert(0, "unidentifiable: no format was "
                        "identified; nothing could be validated")
    result = {"target": args.target, "format": verdict["format"],
              "sha256": verdict["sha256"], "valid": not notes,
              "notes": notes}
    structure = formats.archive_structure_summary(
        args.target, verdict["format"])
    if structure is not None:
        result["structure"] = structure
    return result


def cmd_extract(args):
    return safearchive.safe_extract(args.target, args.out)


def cmd_duplicates(args):
    paths = list(args.files or [])
    if args.dir and not os.path.isdir(args.dir):
        # A nonexistent scan directory previously
        # reported "scanned 0" with exit 0 (D-15).
        raise FileNotFoundError(
            f"no such directory: {args.dir}")
    if args.dir:
        for root, _dirs, files in os.walk(args.dir):
            for name in files:
                paths.append(os.path.join(root, name))
    by_hash = {}
    errors = []
    for path in sorted(paths):
        try:
            by_hash.setdefault(sha256_of(path), []).append(path)
        except OSError as e:
            errors.append({"path": path, "error": str(e)})
    groups = [{"sha256": h, "files": fs}
              for h, fs in by_hash.items() if len(fs) > 1]
    return {"scanned": len(paths), "duplicate_groups": groups,
            "errors": errors}


def human(data, mode):
    if mode == "identify":
        print(f"Format:     {data['format']} "
              f"(confidence: {data['confidence']})")
        print(f"SHA-256:    {data['sha256']}")
        print(f"Size:       {data['size_bytes']:,} bytes")
        for ev in data["evidence"]:
            print(f"  evidence: {ev}")
        if data.get("extension_mismatch"):
            print(f"  WARNING: extension {data['extension']} does "
                  "not match the identified format")
        for note in data.get("validation_notes", []):
            print(f"  note: {note}")
    elif mode == "validate":
        print(f"{data['target']}: format={data['format']} "
              f"valid={data['valid']}")
        for note in data["notes"]:
            print(f"  note: {note}")
        st = data.get("structure")
        if st:
            mf = "yes" if st["has_manifest_mf"] else "no"
            print(f"  structure: {st['entry_count']} entries, "
                  f"{st['class_entries']} class entries, "
                  f"MANIFEST.MF={mf}")
            if st["format"] == "aar":
                am = "yes" if st["has_android_manifest"] else "no"
                cj = "yes" if st["has_classes_jar"] else "no"
                rt = "yes" if st["has_r_txt"] else "no"
                print(f"  aar: AndroidManifest.xml={am}, "
                      f"classes.jar={cj} "
                      f"({st['classes_jar_class_count']} classes), "
                      f"R.txt={rt}, res/ entries={st['res_entries']}, "
                      f"jni libs={len(st['jni_libraries'])}")
    elif mode == "extract":
        print(f"Extracted {len(data['extracted'])} file(s), "
              f"{data['totals']['bytes']:,} bytes")
        for rej in data["rejected"]:
            print(f"  REJECTED {rej['entry']}: {rej['reason']}")
        for name in data["nested_archives"]:
            print(f"  nested archive (not auto-opened): {name}")
    elif mode == "duplicates":
        print(f"Scanned {data['scanned']} file(s); "
              f"{len(data['duplicate_groups'])} duplicate group(s)")
        for group in data["duplicate_groups"]:
            print(f"  {group['sha256'][:16]}… x{len(group['files'])}")
            for path in group["files"]:
                print(f"    {path}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR universal input: identify, validate, "
                    "safe-extract, and find duplicates.")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("identify", "validate"):
        sp = sub.add_parser(name)
        sp.add_argument("target")
        sp.add_argument("--json", action="store_true")
    sp = sub.add_parser("extract")
    sp.add_argument("target")
    sp.add_argument("--out", required=True)
    sp.add_argument("--json", action="store_true")
    sp = sub.add_parser("duplicates")
    sp.add_argument("files", nargs="*")
    sp.add_argument("--dir")
    sp.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    handler = {"identify": cmd_identify, "validate": cmd_validate,
               "extract": cmd_extract,
               "duplicates": cmd_duplicates}[args.command]
    try:
        data = handler(args)
    except FileNotFoundError as e:
        print(f"nar-input: {e}", file=sys.stderr)
        return 2
    except zipfile.BadZipFile as e:
        # A non-archive target for extract is a usage
        # error (exit 2), not a traceback (C-13).
        print(f"nar-input: not a readable archive: {e}",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        human(data, args.command)
    if args.command == "validate":
        return 0 if data["valid"] else 1
    if args.command == "extract":
        if any(r["entry"] == "(whole archive)"
               for r in data["rejected"]):
            return 1
        if data["rejected"] and not data["extracted"]:
            # Every entry rejected: the extraction
            # produced nothing, which is a failure, not
            # a success with notes (C-13).
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
