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

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

DEX_RE = re.compile(r"^(base/dex/)?classes\d*\.dex$")
SO_RE = re.compile(r"^(base/)?lib/([^/]+)/(.+\.so)$")
ARSC_RE = re.compile(r"^(base/)?resources\.arsc$")

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
# Domain must be real labels (no leading dot/hyphen) with a dot + TLD.
EMAIL_RE = re.compile(
    r"[A-Za-z0-9_%+\-][A-Za-z0-9._%+\-]*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}")
# An IP must not be part of a longer dotted-numeric sequence (versions
# like 1.0.4.5.2); octet range is validated in classify().
IP_RE = re.compile(r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9.])")
API_RE = re.compile(r"/(?:api|v\d+|graphql|rest|oauth|auth)(?:/[\w\-./?=&%~]*)?")
PACKAGE_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}\b")
UNIX_PATH_RE = re.compile(r"/(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]*")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\s]+\\)+[^\\\s]*")
# Key-like PATTERNS (presence only -- never proof of a real secret):
# The assigned value (group 2) must look like a value: it contains a
# digit, or is at least 12 chars. Plain English after a colon ("invalid
# token: skipping.") is a log sentence, not an assignment.
KEY_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|token|passwd|password|auth[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*(\S{6,})")
KEY_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{16,}")
KEY_TOKEN_RE = re.compile(
    r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9_\-+=.]{40,}")
# Long hex runs are tokens or hashes: MD5 (32), SHA-1 (40), SHA-256 (64).
# Lowercase-only hex is common for API keys and must not be missed. The
# run is bounded to token sizes and must not be part of a longer hex run.
KEY_HEX_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])",
                        re.IGNORECASE)
# Keyword-prefixed tokens: demo_token_<hex>, api_key_<...>, secret-<...>.
KEY_PREFIXED_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|token|passwd|password|auth[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)[_-][A-Za-z0-9_\-.]{16,}")
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


def _token_candidate_ok(tok):
    """Reject identifier-like floods from the mixed-token pattern.

    Native symbol tables are full of 40+ char names that are code, not
    tokens: C++ mangled names (`_ZN...`), snake/Camel identifiers
    (`K2_GetTimer...`, `OnRep_...`). Real random tokens rarely carry
    those shapes.
    """
    if tok.startswith("_Z"):
        return False
    if tok.count("_") >= 2:
        return False
    if re.search(r"_[A-Z]", tok):
        return False
    # Dotted identifiers (theme/style/class names such as
    # Animation.Material3.SideSheetDialog.Left) are names, not tokens:
    # 3+ short word-like segments give them away. A JWT's segments are
    # long base64url runs, so this does not hide those.
    segs = tok.split(".")
    if len(segs) >= 3 and all(len(s) <= 30 for s in segs):
        return False
    return True


def _looks_like_key(s):
    """Key-like PATTERN test (presence only -- never proof of a real secret)."""
    m = KEY_ASSIGN_RE.search(s)
    if m:
        value = m.group(2)
        if any(c.isdigit() for c in value) or len(value) >= 12:
            return True
    if KEY_BEARER_RE.search(s):
        return True
    if PERCENT_TABLE_RE.search(s):
        return False
    m = KEY_PREFIXED_RE.search(s)
    if m and len(m.group(0)) <= MAX_TOKEN_LEN:
        return True
    # A whitespace-led run of almost pure hex is a chunk of a constant
    # table (crypto test vectors stored as text), not a discrete token.
    stripped = s.strip()
    is_hex_chunk = (s[:1].isspace() and len(stripped) >= 32
                    and sum(1 for c in stripped
                            if c in "0123456789abcdefABCDEF")
                    >= 0.9 * len(stripped))
    # A bare hex run only counts when it mixes digits and a-f letters.
    # All-digit runs are decimal constants (or ASCII digits hex-encoded
    # inside binary tables), and all-letter runs are table data; real
    # hex-encoded tokens (MD5/SHA digests, API keys) mix both.
    m = KEY_HEX_RE.search(s)
    if m and len(m.group(0)) <= MAX_TOKEN_LEN and not is_hex_chunk:
        run = m.group(0)
        if any(c.isdigit() for c in run) and any(c in "abcdefABCDEF" for c in run):
            return True
    m = KEY_TOKEN_RE.search(s)
    return bool(m) and len(m.group(0)) <= MAX_TOKEN_LEN \
        and not is_hex_chunk and _token_candidate_ok(m.group(0))


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
    # An API path only counts when it starts the string or follows a
    # separator. Inside a longer path (`Lcom/google/api/Client;`, DEX
    # class descriptors, slash-form class names) `/api/` is a package
    # segment, not an endpoint -- those flooded this group before.
    for m in API_RE.finditer(s):
        prev = s[m.start() - 1] if m.start() else ""
        if not prev or not (prev.isalnum() or prev in "_/$."):
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
    zf.close()

    # Container inputs resolve through narlib.container: the
    # scan runs on the base APK plus every merged split
    # (split sources are named "<archive>:<member>"), never
    # on the container file itself as if it were an APK.
    scan_paths = [(apk_path, "")]
    resolved = None
    if container_mod.detect_container(apk_path) in \
            container_mod.CONTAINER_KINDS:
        resolved = container_mod.resolve_target(apk_path)
        scan_paths = [(resolved.base, "")] + [
            (s["path"], os.path.basename(s["path"]) + ":")
            for s in resolved.splits]
        result["container"] = resolved.container_block()

    sources = {}          # entry name -> raw string count
    found = {}            # string -> set of source entries
    total_raw = 0
    try:
        for scan_path, prefix in scan_paths:
            with zipfile.ZipFile(scan_path) as zf:
                targets = [n for n in zf.namelist()
                           if DEX_RE.match(n) or SO_RE.match(n)
                           or ARSC_RE.match(n)]
                for name in targets:
                    try:
                        data = read_member_capped(zf, name)
                    except (KeyError, zipfile.BadZipFile,
                            OSError, ValueError):
                        continue
                    count = 0
                    label = prefix + name
                    for s in extract_runs(data, min_length):
                        count += 1
                        if s in found:
                            found[s].add(label)
                        else:
                            found[s] = {label}
                    sources[label] = count
                    total_raw += count
    finally:
        if resolved is not None:
            resolved.cleanup()

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
            value = hit["value"]
            if len(value) > 300:  # one glued binary run must not flood the page
                value = value[:300] + f"... [{len(hit['value'])} chars]"
            lines.append(f"  - {value}  [{src}{extra}]")
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
