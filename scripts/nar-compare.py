#!/usr/bin/env python3
"""nar-compare.py: compare two APK versions without apktool or jadx.

Stdlib-only, no pip dependencies. Reads both APKs as ZIPs (never executes
them) and diffs identity, DEX structure, native libraries, resources, assets,
and signing-file lists.

Usage:
    python3 nar-compare.py old.apk new.apk [--json]

What is compared:
    - Identity: package name / version / SDK levels from `aapt2 dump badging`
      when aapt2 is available (graceful "unavailable" note when it is not),
      plus manifest presence and permissions added/removed.
    - DEX: file list plus method/class/string counts read straight from the
      DEX header (little-endian uint32: string_ids_size @0x38, type_ids_size
      @0x40, proto_ids_size @0x48, field_ids_size @0x50, method_ids_size
      @0x58, class_defs_size @0x60). Offsets verified against real DEX files.
    - Native libs: per-ABI lists with sizes and SHA-256 of entry bytes;
      added / removed / changed (same path, different hash).
    - resources.arsc presence, size, and SHA-256; asset / res / entry counts.
    - Signing files (META-INF *.RSA/.DSA/.EC/.SF/.MF): added / removed /
      changed. Listed for analysis only -- this tool never touches signing.
    - Full ZIP entry diff: added / removed / changed entries by SHA-256.

Exit codes: 0 = compared OK (differences are the point, not an error),
1 = one of the files is not a valid ZIP/APK container, 2 = missing or
unreadable file.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

DEX_RE = re.compile(r"^(base/dex/)?classes\d*\.dex$")
SO_RE = re.compile(r"^(base/)?lib/([^/]+)/(.+\.so)$")
SIGNING_EXTS = (".RSA", ".DSA", ".EC", ".SF", ".MF")
BADGING_PATTERNS = {
    "package": re.compile(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'"),
    "sdk": re.compile(r"^(?:minSdkVersion|sdkVersion):'([^']+)'"),
    "target_sdk": re.compile(r"^targetSdkVersion:'([^']+)'"),
    "app_label": re.compile(r"^application-label:'([^']*)'"),
}
# DEX header counts: (field, offset). Verified against real DEX files
# (observed on test samples: 1667 methods / 234 classes; 2544 / 429).
DEX_HEADER_FIELDS = [
    ("string_count", 0x38),
    ("type_count", 0x40),
    ("proto_count", 0x48),
    ("field_count", 0x50),
    ("method_count", 0x58),
    ("class_count", 0x60),
]


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_stream(fp):
    h = hashlib.sha256()
    for chunk in iter(lambda: fp.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def find_aapt2():
    aapt2 = shutil.which("aapt2")
    if aapt2:
        return aapt2
    for root in filter(None, [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/workspace/android-sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]):
        bt = os.path.join(root, "build-tools")
        if os.path.isdir(bt):
            def _ver_key(v):
                try:
                    return tuple(int(x) for x in v.split("."))
                except ValueError:
                    return (0,)
            for ver in sorted(os.listdir(bt), key=_ver_key, reverse=True):
                cand = os.path.join(bt, ver, "aapt2")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
    return None


def aapt2_badging(apk_path):
    """Best-effort package identity via aapt2.

    Returns (info_dict, status) where status is "ok", "not-found", or
    "unreadable" (aapt2 ran but could not read badging for this file).
    """
    aapt2 = find_aapt2()
    if not aapt2:
        return {}, "not-found"
    try:
        out = subprocess.run(
            [aapt2, "dump", "badging", apk_path],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}, "unreadable"
    if out.returncode != 0:
        return {}, "unreadable"
    info = {}
    permissions = []
    sdk_pairs = []
    for line in out.stdout.splitlines():
        m = BADGING_PATTERNS["package"].match(line)
        if m:
            info["package"] = m.group(1)
            info["version_code"] = m.group(2)
            info["version_name"] = m.group(3)
            continue
        m = BADGING_PATTERNS["sdk"].match(line)
        if m:
            # First <uses-sdk> wins (a manifest can carry duplicates);
            # every pair is recorded so a duplicate is visible, in
            # agreement with nar-triage and nar-perms.
            sdk_pairs.append({"min_sdk": m.group(1)})
            if "min_sdk" not in info:
                info["min_sdk"] = m.group(1)
            continue
        m = BADGING_PATTERNS["target_sdk"].match(line)
        if m:
            if sdk_pairs:
                sdk_pairs[-1]["target_sdk"] = m.group(1)
            if "target_sdk" not in info:
                info["target_sdk"] = m.group(1)
            continue
        m = BADGING_PATTERNS["app_label"].match(line)
        if m:
            info["app_label"] = m.group(1)
            continue
        if line.startswith("uses-permission:"):
            pm = re.search(r"name='([^']+)'", line)
            if pm:
                permissions.append(pm.group(1))
    if permissions:
        info["permissions"] = sorted(set(permissions))
    if len(sdk_pairs) > 1:
        info["sdk_pairs"] = sdk_pairs
    return info, "ok"


def dex_header_counts(header):
    """Read DEX counts from the first 112 header bytes, or None if invalid."""
    if len(header) < 112 or header[:3] != b"dex":
        return None
    try:
        return {name: struct.unpack_from("<I", header, off)[0]
                for name, off in DEX_HEADER_FIELDS}
    except struct.error:
        return None


def inventory(apk_path):
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    inv = {
        "file": os.path.basename(apk_path),
        "path": os.path.abspath(apk_path),
        "sha256": sha256_of(apk_path),
        "size_bytes": os.path.getsize(apk_path),
    }
    try:
        zf = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        inv["error"] = "not a valid ZIP/APK container"
        return inv

    with zf:
        names = zf.namelist()
        infos = {i.filename: i for i in zf.infolist()}
        dex, native, signing = [], {}, []
        assets = res = other = 0
        arsc = None
        entry_hashes = {}
        for name in names:
            info = infos[name]
            if name.endswith("/"):
                continue
            with zf.open(name) as fp:
                digest = sha256_stream(fp)
            entry_hashes[name] = {"size_bytes": info.file_size, "sha256": digest}
            if DEX_RE.match(name):
                with zf.open(name) as fp:
                    counts = dex_header_counts(fp.read(112))
                dex.append({"name": name, "size_bytes": info.file_size,
                            "counts": counts})
            elif (m := SO_RE.match(name)):
                native.setdefault(m.group(2), []).append(
                    {"name": m.group(3), "path": name,
                     "size_bytes": info.file_size, "sha256": digest})
            elif name == "resources.arsc":
                arsc = {"size_bytes": info.file_size, "sha256": digest}
            if name.startswith("META-INF/") and name.upper().endswith(SIGNING_EXTS):
                signing.append({"name": name, "size_bytes": info.file_size,
                                "sha256": digest})
            elif re.match(r"^(base/)?assets/", name):
                assets += 1
            elif re.match(r"^(base/)?res/", name):
                res += 1
            elif not (DEX_RE.match(name) or SO_RE.match(name)
                      or name.startswith("META-INF/")
                      or name in ("AndroidManifest.xml", "resources.arsc")):
                other += 1

        totals = {name: 0 for name, _ in DEX_HEADER_FIELDS}
        for d in dex:
            if d["counts"]:
                for k in totals:
                    totals[k] += d["counts"][k]
        inv.update({
            "zip_entries": len(names),
            "has_manifest": "AndroidManifest.xml" in infos,
            "resources_arsc": arsc,
            "dex_files": sorted(dex, key=lambda d: d["name"]),
            "dex_count": len(dex),
            "dex_total_bytes": sum(d["size_bytes"] for d in dex),
            "dex_totals": totals,
            "native_libs_by_abi": {abi: sorted(libs, key=lambda l: l["name"])
                                   for abi, libs in sorted(native.items())},
            "native_lib_count": sum(len(v) for v in native.values()),
            "signing_files": sorted(signing, key=lambda s: s["name"]),
            "asset_count": assets,
            "resource_file_count": res,
            "other_file_count": other,
            "entry_hashes": entry_hashes,
        })
    badging, badging_status = aapt2_badging(apk_path)
    inv["badging"] = badging
    inv["badging_status"] = badging_status
    return inv


def _diff_lists(old, new, key):
    """Added/removed/changed between two lists of dicts keyed by `key`.

    Changed = same key, different content (compared as full dicts).
    Returns (added, removed, changed) where changed holds (old, new) pairs.
    """
    old_map = {item[key]: item for item in old}
    new_map = {item[key]: item for item in new}
    added = [new_map[k] for k in sorted(set(new_map) - set(old_map))]
    removed = [old_map[k] for k in sorted(set(old_map) - set(new_map))]
    changed = [(old_map[k], new_map[k]) for k in sorted(set(old_map) & set(new_map))
               if old_map[k] != new_map[k]]
    return added, removed, changed


def _diff_hashes(old_hashes, new_hashes):
    old_keys, new_keys = set(old_hashes), set(new_hashes)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = sorted(k for k in old_keys & new_keys
                     if old_hashes[k]["sha256"] != new_hashes[k]["sha256"])
    return added, removed, changed


def compare(old_path, new_path):
    old, new = inventory(old_path), inventory(new_path)
    report = {"old": old, "new": new, "identical_files": old.get("sha256") == new.get("sha256")}
    if "error" in old or "error" in new:
        return report

    old_libs = [lib for libs in old["native_libs_by_abi"].values() for lib in libs]
    new_libs = [lib for libs in new["native_libs_by_abi"].values() for lib in libs]
    libs_added, libs_removed, libs_changed = _diff_lists(old_libs, new_libs, "path")
    dex_added, dex_removed, dex_changed = _diff_lists(
        old["dex_files"], new["dex_files"], "name")
    sign_added, sign_removed, sign_changed = _diff_lists(
        old["signing_files"], new["signing_files"], "name")
    ent_added, ent_removed, ent_changed = _diff_hashes(
        old["entry_hashes"], new["entry_hashes"])

    old_perms = set(old["badging"].get("permissions", []))
    new_perms = set(new["badging"].get("permissions", []))

    arsc_old, arsc_new = old["resources_arsc"], new["resources_arsc"]
    arsc_status = ("unchanged" if arsc_old == arsc_new else
                   "added" if arsc_old is None else
                   "removed" if arsc_new is None else "changed")

    report["diff"] = {
        "size_delta_bytes": new["size_bytes"] - old["size_bytes"],
        "entry_count_delta": new["zip_entries"] - old["zip_entries"],
        "identity_changed": old["badging"] != new["badging"],
        "manifest_changed": old["has_manifest"] != new["has_manifest"],
        "permissions_added": sorted(new_perms - old_perms),
        "permissions_removed": sorted(old_perms - new_perms),
        "dex": {
            "added": dex_added, "removed": dex_removed,
            "changed": [{"name": o["name"], "old": o, "new": n}
                        for o, n in dex_changed],
            "totals_delta": {k: new["dex_totals"][k] - old["dex_totals"][k]
                             for k in old["dex_totals"]},
            "total_bytes_delta": new["dex_total_bytes"] - old["dex_total_bytes"],
        },
        "native_libs": {
            "added": libs_added, "removed": libs_removed,
            "changed": [{"path": o["path"], "old": o, "new": n}
                        for o, n in libs_changed],
        },
        "resources_arsc": {"status": arsc_status,
                           "old": arsc_old, "new": arsc_new},
        "counts_delta": {
            "assets": new["asset_count"] - old["asset_count"],
            "resources": new["resource_file_count"] - old["resource_file_count"],
            "other": new["other_file_count"] - old["other_file_count"],
            "native_libs": new["native_lib_count"] - old["native_lib_count"],
        },
        "signing_files": {
            "added": sign_added, "removed": sign_removed,
            "changed": [{"name": o["name"], "old": o, "new": n}
                        for o, n in sign_changed],
        },
        "entries": {
            "added": ent_added, "removed": ent_removed, "changed": ent_changed,
            "added_count": len(ent_added), "removed_count": len(ent_removed),
            "changed_count": len(ent_changed),
        },
    }
    return report


def _fmt_delta(n, unit=""):
    sign = "+" if n > 0 else ""
    return f"{sign}{n:,}{unit}"


def _identity_line(inv):
    b = inv.get("badging") or {}
    if b:
        return (f"{b.get('package', '?')} v{b.get('version_name', '?')} "
                f"(code {b.get('version_code', '?')}), "
                f"min SDK {b.get('min_sdk', '?')} / target {b.get('target_sdk', '?')}")
    if inv.get("badging_status") == "not-found":
        return "(aapt2 not found; identity unavailable)"
    return "(aapt2 could not read badging for this file)"


def _show_names(lines, label, names, limit=20):
    if not names:
        return
    lines.append(f"  {label} ({len(names)}):")
    for n in names[:limit]:
        lines.append(f"    - {n}")
    if len(names) > limit:
        lines.append(f"    ... and {len(names) - limit} more (see --json)")


def human(report):
    old, new = report["old"], report["new"]
    title = f"NAR compare: {old['file']}  ->  {new['file']}"
    lines = [title, "=" * len(title)]
    for tag, inv in (("OLD", old), ("NEW", new)):
        if inv.get("error"):
            lines.append(f"{tag} {inv['file']}: ERROR: {inv['error']}")
            return "\n".join(lines)
    lines.append(f"OLD: {old['file']}  ({old['size_bytes']:,} bytes, "
                 f"SHA-256 {old['sha256'][:16]}...)")
    lines.append(f"     {_identity_line(old)}")
    lines.append(f"NEW: {new['file']}  ({new['size_bytes']:,} bytes, "
                 f"SHA-256 {new['sha256'][:16]}...)")
    lines.append(f"     {_identity_line(new)}")
    if report["identical_files"]:
        lines.append("\nFiles are BYTE-IDENTICAL (same SHA-256). No differences.")
        return "\n".join(lines)
    d = report["diff"]
    lines.append(f"\nSize: {_fmt_delta(d['size_delta_bytes'], ' bytes')}  |  "
                 f"ZIP entries: {_fmt_delta(d['entry_count_delta'])}  |  "
                 f"identity changed: {'YES' if d['identity_changed'] else 'no'}  |  "
                 f"manifest present: {'yes' if old['has_manifest'] else 'NO'} -> "
                 f"{'yes' if new['has_manifest'] else 'NO'}")
    if d["permissions_added"] or d["permissions_removed"]:
        lines.append(f"Permissions added: {', '.join(d['permissions_added']) or '(none)'}")
        lines.append(f"Permissions removed: {', '.join(d['permissions_removed']) or '(none)'}")
    else:
        lines.append("Permissions: unchanged")

    dd = d["dex"]
    lines.append(f"\nDEX: {old['dex_count']} -> {new['dex_count']} file(s), "
                 f"{_fmt_delta(dd['total_bytes_delta'], ' bytes')}")
    for k, label in (("method_count", "methods"), ("class_count", "classes"),
                     ("string_count", "strings"), ("field_count", "fields")):
        lines.append(f"  {label}: "
                     f"{old['dex_totals'][k]:,} -> {new['dex_totals'][k]:,} "
                     f"({_fmt_delta(dd['totals_delta'][k])})")
    for item in dd["added"]:
        lines.append(f"  + DEX added: {item['name']} ({item['size_bytes']:,} bytes)")
    for item in dd["removed"]:
        lines.append(f"  - DEX removed: {item['name']}")
    for c in dd["changed"]:
        o, n = c["old"], c["new"]
        m = (f"{o['counts']['method_count']} -> {n['counts']['method_count']} methods"
             if o["counts"] and n["counts"] else "header unreadable")
        lines.append(f"  ~ DEX changed: {c['name']} ({o['size_bytes']:,} -> "
                     f"{n['size_bytes']:,} bytes, {m})")

    nl = d["native_libs"]
    lines.append(f"\nNative libs: {old['native_lib_count']} -> "
                 f"{new['native_lib_count']} file(s)")
    for lib in nl["added"]:
        lines.append(f"  + added: {lib['path']} ({lib['size_bytes']:,} bytes)")
    for lib in nl["removed"]:
        lines.append(f"  - removed: {lib['path']} ({lib['size_bytes']:,} bytes)")
    for c in nl["changed"]:
        lines.append(f"  ~ changed: {c['path']} ({c['old']['size_bytes']:,} -> "
                     f"{c['new']['size_bytes']:,} bytes, SHA-256 differs)")
    if not (nl["added"] or nl["removed"] or nl["changed"]):
        lines.append("  (unchanged)")

    arsc = d["resources_arsc"]
    lines.append(f"\nresources.arsc: {arsc['status']}"
                 + (f" ({arsc['old']['size_bytes']:,} -> "
                    f"{arsc['new']['size_bytes']:,} bytes)"
                    if arsc["status"] == "changed" else ""))
    cd = d["counts_delta"]
    lines.append(f"Counts delta: assets {_fmt_delta(cd['assets'])}, "
                 f"res/ {_fmt_delta(cd['resources'])}, "
                 f"other {_fmt_delta(cd['other'])}, "
                 f"native libs {_fmt_delta(cd['native_libs'])}")

    sf = d["signing_files"]
    lines.append(f"\nSigning files (META-INF, analysis only): "
                 f"{len(old['signing_files'])} -> {len(new['signing_files'])}")
    for s in sf["added"]:
        lines.append(f"  + added: {s['name']}")
    for s in sf["removed"]:
        lines.append(f"  - removed: {s['name']}")
    for c in sf["changed"]:
        lines.append(f"  ~ changed: {c['name']} (SHA-256 differs)")
    if not (sf["added"] or sf["removed"] or sf["changed"]):
        lines.append("  (unchanged)")

    ent = d["entries"]
    lines.append(f"\nZIP entries: +{ent['added_count']} added, "
                 f"-{ent['removed_count']} removed, "
                 f"~{ent['changed_count']} changed (by SHA-256)")
    _show_names(lines, "added", ent["added"])
    _show_names(lines, "removed", ent["removed"])
    _show_names(lines, "changed", ent["changed"])
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR compare: diff two APK versions without apktool or jadx.")
    p.add_argument("old_apk", help="path to the older .apk file")
    p.add_argument("new_apk", help="path to the newer .apk file")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = p.parse_args(argv)
    try:
        report = compare(args.old_apk, args.new_apk)
    except FileNotFoundError as e:
        print(f"nar-compare: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"nar-compare: cannot read file: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    bad = ("error" in report["old"]) or ("error" in report["new"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
