#!/usr/bin/env python3
"""nar-strings.py: extract and rank interesting strings from an APK.

Stdlib-only, no pip dependencies. Reads the APK as a ZIP (never executes it)
and pulls printable strings (ASCII and UTF-16LE runs, minimum length 4 by
default) from DEX files, native libraries (.so), and resources.arsc bytes.
Each unique string is classified into one ranked group:

    urls            http(s) URLs
    key_patterns    KEY-LIKE PATTERNS ONLY -- a match means the string LOOKS
                    like a key/token/secret assignment or a long mixed token.
                    It is evidence of presence, NOT proof of a real secret.
                    Verify any hit before treating it as a credential.
    emails          email addresses
    ips             IPv4 addresses
    api_endpoints   /api/..., /v1/..., /graphql, /rest/, /oauth, /auth paths
    package_names   dotted identifiers with 3+ segments (com.example.app)
    file_paths      absolute Unix / Android paths and Windows paths
    other           everything else (shown last; counts only in brief mode)

Usage:
    python3 nar-strings.py app.apk [--json] [--min-length N] [--limit N]
    python3 nar-strings.py app.apk --json > strings.json

Human output shows ranked groups with counts and the most interesting hits
first (longest first within a group); --json prints the full classification.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import sys
import zipfile

DEX_RE = re.compile(r"^(base/dex/)?classes\d*\.dex$")
SO_RE = re.compile(r"^(base/)?lib/([^/]+)/(.+\.so)$")
ARSC_RE = re.compile(r"^(base/)?resources\.arsc$")

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
API_RE = re.compile(r"/(?:api|v\d+|graphql|rest|oauth|auth)(?:/[\w\-./?=&%~]*)?")
PACKAGE_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}\b")
UNIX_PATH_RE = re.compile(r"/(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]*")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\s]+\\)+[^\\\s]*")
# Key-like PATTERNS (presence only -- never proof of a real secret):
KEY_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|token|passwd|password|auth[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S{6,}")
KEY_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{16,}")
KEY_TOKEN_RE = re.compile(
    r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9_\-+=.]{32,}")
# Tokens longer than this are almost always concatenated runs in .so
# binaries, not real tokens. Percent-encoded tables are data, not keys.
MAX_TOKEN_LEN = 256
PERCENT_TABLE_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
# A slash-path only counts as a file path when it starts at a known
# Android/Unix root or ends in a dotted filename -- otherwise DEX class
# paths like /org/commonmark/internal/... flood the group.
PATH_ROOTS = ("data", "system", "sdcard", "storage", "proc", "dev", "cache",
              "mnt", "etc", "vendor", "apex", "product", "odm", "oem", "acct",
              "config", "usr", "var", "opt", "home", "tmp", "bin", "lib",
              "sbin", "private", "android_asset", "res", "assets")

# Display order: most interesting first.
GROUP_ORDER = ["urls", "key_patterns", "emails", "ips", "api_endpoints",
               "package_names", "file_paths", "other"]
GROUP_TITLES = {
    "urls": "URLs",
    "key_patterns": "Key-like PATTERNS (presence only -- verify before trusting)",
    "emails": "Email addresses",
    "ips": "IP addresses",
    "api_endpoints": "API endpoints / paths",
    "package_names": "Package names / dotted identifiers",
    "file_paths": "File paths",
    "other": "Other strings",
}


def extract_runs(data, min_length):
    """Yield printable strings from raw bytes: ASCII runs and UTF-16LE runs."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    for m in ascii_re.finditer(data):
        yield m.group().decode("ascii")
    for m in utf16_re.finditer(data):
        yield m.group().decode("utf-16-le")


def _is_file_path(path):
    """True if a slash-path looks like a real file path, not a class path."""
    parts = [p for p in path.split("/") if p]
    if not parts:
        return False
    if parts[0] in PATH_ROOTS:
        return True
    return "." in parts[-1]


def _looks_like_key(s):
    """Key-like PATTERN test (presence only -- never proof of a real secret)."""
    if KEY_ASSIGN_RE.search(s) or KEY_BEARER_RE.search(s):
        return True
    if PERCENT_TABLE_RE.search(s):
        return False
    m = KEY_TOKEN_RE.search(s)
    return bool(m) and len(m.group(0)) <= MAX_TOKEN_LEN


def classify(s):
    """Assign a string to its most specific group (first match wins)."""
    m = URL_RE.search(s)
    if m:
        url = m.group(0).rstrip(".,;:!?)]")
        # Adjacent strings in .so binaries can run together; a second
        # "://" inside one match means two URLs got concatenated.
        second = url.find("://", url.find("://") + 3)
        if second != -1:
            cut = url.rfind("http", 0, second)
            url = url[:cut] if cut > 0 else url[:second]
        if len(url) > len(url.split("://")[0]) + 3:  # a host must remain
            return "urls", url
    if EMAIL_RE.search(s):
        return "emails", EMAIL_RE.search(s).group(0)
    m = IP_RE.search(s)
    if m:
        ip = m.group(0)
        octets = ip.split(".")
        # Real IPs have no leading-zero octets (02.13.03.13 is a version tuple).
        if (all(0 <= int(o) <= 255 for o in octets)
                and all(len(o) == 1 or not o.startswith("0") for o in octets)):
            return "ips", ip
    if _looks_like_key(s):
        return "key_patterns", s
    m = API_RE.search(s)
    if m:
        return "api_endpoints", m.group(0)
    m = PACKAGE_RE.search(s)
    if m:
        return "package_names", m.group(0)
    m = UNIX_PATH_RE.search(s) or WIN_PATH_RE.search(s)
    if m and (m.group(0).startswith("/") and _is_file_path(m.group(0))
              or WIN_PATH_RE.match(m.group(0))):
        return "file_paths", m.group(0)
    return "other", s


def _sort_key(group, value):
    """Most interesting first. Key patterns: keyword assignments first,
    then shorter (token-sized) hits before long concatenated runs.
    Other groups: longest first."""
    if group == "key_patterns":
        named = bool(KEY_ASSIGN_RE.search(value) or KEY_BEARER_RE.search(value))
        return (0 if named else 1, len(value), value)
    return (-len(value), value)


def scan(apk_path, min_length):
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    result = {
        "file": os.path.basename(apk_path),
        "path": os.path.abspath(apk_path),
        "size_bytes": os.path.getsize(apk_path),
        "min_length": min_length,
    }
    try:
        zf = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        result["error"] = "not a valid ZIP/APK container"
        return result

    sources = {}          # entry name -> raw string count
    found = {}            # string -> set of source entries
    total_raw = 0
    with zf:
        targets = [n for n in zf.namelist()
                   if DEX_RE.match(n) or SO_RE.match(n) or ARSC_RE.match(n)]
        for name in targets:
            try:
                data = zf.read(name)
            except (KeyError, zipfile.BadZipFile, OSError):
                continue
            count = 0
            for s in extract_runs(data, min_length):
                count += 1
                if s in found:
                    found[s].add(name)
                else:
                    found[s] = {name}
            sources[name] = count
            total_raw += count

    groups = {g: {} for g in GROUP_ORDER}   # group -> {hit: [sources]}
    for s, srcs in found.items():
        group, hit = classify(s)
        groups[group].setdefault(hit, set()).update(srcs)

    result.update({
        "sources_scanned": sorted(sources),
        "source_raw_counts": sources,
        "total_raw_strings": total_raw,
        "unique_strings": len(found),
        "groups": {
            g: {
                "count": len(hits),
                "hits": [
                    {"value": v, "sources": sorted(srcs)}
                    for v, srcs in sorted(
                        hits.items(), key=lambda kv: _sort_key(g, kv[0]))
                ],
            }
            for g, hits in groups.items()
        },
    })
    return result


def human(report, limit):
    title = f"NAR strings: {report['file']}"
    lines = [title, "=" * len(title)]
    if report.get("error"):
        lines.append(f"ERROR: {report['error']}")
        return "\n".join(lines)
    lines.append(f"Size: {report['size_bytes']:,} bytes  |  min length: "
                 f"{report['min_length']}")
    lines.append(f"Sources scanned ({len(report['sources_scanned'])}): "
                 f"{', '.join(report['sources_scanned']) or '(none found)'}")
    lines.append(f"Raw strings: {report['total_raw_strings']:,}  |  "
                 f"unique: {report['unique_strings']:,}")
    lines.append("NOTE: key_patterns are PATTERNS only -- a hit means a string "
                 "LOOKS like a key/token. It is not proof of a real secret.")
    for group in GROUP_ORDER:
        g = report["groups"][group]
        lines.append(f"\n{GROUP_TITLES[group]}: {g['count']:,}")
        if group == "other" and not g["hits"]:
            continue
        for hit in g["hits"][:limit]:
            src = hit["sources"][0]
            extra = f" (+{len(hit['sources']) - 1} more)" if len(hit["sources"]) > 1 else ""
            lines.append(f"  - {hit['value']}  [{src}{extra}]")
        if len(g["hits"]) > limit:
            lines.append(f"  ... and {len(g['hits']) - limit:,} more (see --json)")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR strings: extract and rank interesting strings from an APK.")
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output (full hits)")
    p.add_argument("--min-length", type=int, default=4,
                   help="minimum string length (default: 4)")
    p.add_argument("--limit", type=int, default=15,
                   help="max hits shown per group in human output (default: 15)")
    args = p.parse_args(argv)
    if args.min_length < 1:
        print("nar-strings: --min-length must be >= 1", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("nar-strings: --limit must be >= 0", file=sys.stderr)
        return 2
    try:
        report = scan(args.apk, args.min_length)
    except FileNotFoundError as e:
        print(f"nar-strings: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"nar-strings: cannot read file: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report, args.limit))
    return 0 if "error" not in report else 1


if __name__ == "__main__":
    sys.exit(main())
