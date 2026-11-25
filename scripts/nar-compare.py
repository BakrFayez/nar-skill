#!/usr/bin/env python3
"""nar-compare.py: compare two APK versions without apktool or jadx.

Stdlib-only, no pip dependencies. Reads both APKs as ZIPs (never executes
them) and diffs identity, DEX structure, native libraries, resources, assets,
and signing-file lists.

Usage:
    python3 nar-compare.py old.apk new.apk [--json]
    python3 nar-compare.py old.apk new.apk --out DIR

With --out DIR (Evolution Phase 7), the comparison is also
written as three named artifacts: comparison.json (this
tool's full report), feature-map.json (the per-dimension
added/removed/modified projection, schema:
schemas/compare-feature-map.schema.json), and
version-diff.md (the human-readable rendering of the same
projection). The feature map's entry dimension separates
signing-file churn from content changes; that separation
is a labeled heuristic — signing files change on every
re-sign, legitimate or not — and the unfiltered counts
stay in comparison.json.

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

Part of NAR (Nirous Android Reversing).
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


def _aapt2_file_names():
    """Candidate aapt2 file names, in preference order.

    The Windows build-tools binary is aapt2.exe (batch
    wrappers also exist in the wild); everywhere else the
    binary is the extensionless ``aapt2``. On Windows the
    extensionless name is still a candidate: a tool planted
    on PATH in script form carries no extension, and
    shutil.which cannot find it there (which() only tries
    the PATHEXT extensions), so find_aapt2 scans PATH
    itself for the names below."""
    if sys.platform == "win32":
        return ("aapt2.exe", "aapt2.bat", "aapt2.cmd", "aapt2")
    return ("aapt2",)


def _aapt2_candidate_ok(cand):
    if not os.path.isfile(cand):
        return False
    if sys.platform == "win32":
        # os.access(X_OK) is not meaningful on Windows;
        # existence is the honest check there.
        return True
    return os.access(cand, os.X_OK)


def _aapt2_argv(aapt2, *args):
    """Command line that runs an aapt2 candidate.

    On POSIX every candidate executes directly, exactly as
    before. Windows cannot CreateProcess anything but a
    native binary: a .bat/.cmd wrapper must go through
    cmd, and an extensionless candidate with a shebang
    (the form a PATH-planted tool takes) must go through
    sh when one is available — with no sh, the bare
    candidate is returned and the caller's OSError handling
    reports the tool unreadable rather than pretending it
    ran."""
    if sys.platform != "win32":
        return [aapt2, *args]
    lower = aapt2.lower()
    if lower.endswith((".bat", ".cmd")):
        return ["cmd", "/c", aapt2, *args]
    if lower.endswith(".exe"):
        return [aapt2, *args]
    try:
        with open(aapt2, "rb") as fh:
            head = fh.read(2)
    except OSError:
        head = b""
    if head == b"#!":
        sh = shutil.which("sh") or shutil.which("bash")
        if sh:
            return [sh, aapt2, *args]
    return [aapt2, *args]


def find_aapt2():
    aapt2 = shutil.which("aapt2")
    if aapt2:
        return aapt2
    # Manual PATH scan: on Windows which() misses candidates
    # whose names carry no PATHEXT extension (see
    # _aapt2_file_names); on POSIX this is only a fallback
    # for the same names which() would have tried.
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        for name in _aapt2_file_names():
            cand = os.path.join(entry, name)
            if _aapt2_candidate_ok(cand):
                return cand
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
                for name in _aapt2_file_names():
                    cand = os.path.join(bt, ver, name)
                    if _aapt2_candidate_ok(cand):
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
            _aapt2_argv(aapt2, "dump", "badging", apk_path),
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
    try:
        report["extended"] = extended_compare(old_path, new_path,
                                              report)
    except Exception as e:  # extended diff must never break 1.x
        report["extended"] = {"notes": [f"extended comparison "
                                         f"failed: {e}"]}
    return report


def _run_json_tool(script, args, timeout=1800):
    here = os.path.dirname(os.path.abspath(__file__))
    cmd = [sys.executable, os.path.join(here, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        if proc.returncode != 0:
            # A failed tool's stdout is an error document,
            # not a result: returning it let a bad target
            # produce an empty-but-successful report
            # downstream (stability audit D-02).
            return None
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS", "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
}


def extended_compare(old_path, new_path, report):
    """Brief section 13: semantic diffs + severity + similarity.

    Runs the DEX/strings/triage tools as subprocesses (the 1.x
    standalone pattern) and degrades to a note when a tool
    cannot run, instead of failing the whole comparison."""
    ext = {"notes": []}
    old_h = report["old"].get("entry_hashes") or {}
    new_h = report["new"].get("entry_hashes") or {}
    union = set(old_h) | set(new_h)
    same = sum(1 for k in set(old_h) & set(new_h)
               if old_h[k]["sha256"] == new_h[k]["sha256"])
    ext["similarity"] = {
        "entry_jaccard_identical": (round(same / len(union), 4)
                                    if union else 1.0),
        "identical_entries": same, "total_entries_union": len(union)}
    asset_old = {k: v for k, v in old_h.items()
                 if "/assets/" in k or k.startswith("assets/")}
    asset_new = {k: v for k, v in new_h.items()
                 if "/assets/" in k or k.startswith("assets/")}
    a_add, a_rem, a_chg = _diff_hashes(asset_old, asset_new)
    ext["assets"] = {"added": a_add[:50], "removed": a_rem[:50],
                     "changed": a_chg[:50],
                     "added_count": len(a_add),
                     "removed_count": len(a_rem),
                     "changed_count": len(a_chg)}

    def class_set(path):
        data = _run_json_tool("nar-dex.py", [path])
        if not data:
            return None
        out = set()
        for d in data.get("dex_files", []):
            for c in d.get("classes", []):
                out.add(c["class"])
        return out

    old_classes, new_classes = class_set(old_path), class_set(new_path)
    if old_classes is not None and new_classes is not None:
        ext["classes"] = {
            "added_count": len(new_classes - old_classes),
            "removed_count": len(old_classes - new_classes),
            "added_sample": sorted(new_classes - old_classes)[:25],
            "removed_sample": sorted(old_classes - new_classes)[:25]}
    else:
        ext["notes"].append("class diff unavailable (nar-dex "
                            "could not run on one side)")

    def endpoint_set(path):
        data = _run_json_tool("nar-strings.py", [path])
        if not data:
            return None
        out = set()
        # nar-strings groups are {name: {"count", "hits"}} —
        # iterating the group dict itself yields its keys,
        # which silently produced identical sets on both
        # sides (found in Evolution Phase 7: the endpoint
        # diff reported 0/0 on a pair with a real change).
        for group in ("urls", "api_endpoints"):
            g = data.get("groups", {}).get(group) or {}
            hits = g.get("hits", []) if isinstance(g, dict) else g
            for hit in hits:
                out.add(hit.get("value") if isinstance(hit, dict)
                        else hit)
        return out

    old_eps, new_eps = endpoint_set(old_path), endpoint_set(new_path)
    if old_eps is not None and new_eps is not None:
        ext["endpoints"] = {
            "added": sorted(new_eps - old_eps)[:50],
            "removed": sorted(old_eps - new_eps)[:50],
            "added_count": len(new_eps - old_eps),
            "removed_count": len(old_eps - new_eps)}
    else:
        ext["notes"].append("endpoint diff unavailable "
                            "(nar-strings could not run)")

    def engine_versions(path):
        data = _run_json_tool("nar-triage.py", [path])
        if not data:
            return None
        return data.get("engine_versions") or {}

    old_ev, new_ev = engine_versions(old_path), engine_versions(new_path)
    if old_ev is not None and new_ev is not None:
        ext["engine_versions"] = {"old": old_ev, "new": new_ev,
                                  "changed": old_ev != new_ev}

    # Severity classification (brief 13: assign a severity to
    # significant changes, with the reason kept next to it).
    sev = []
    d = report["diff"]
    old_b = report["old"].get("badging") or {}
    new_b = report["new"].get("badging") or {}
    if old_b.get("package") != new_b.get("package"):
        sev.append({"level": "high", "change": "package name changed",
                    "reason": "different application identity"})
    if d["signing_files"]["changed"] or d["signing_files"]["added"] \
            or d["signing_files"]["removed"]:
        sev.append({"level": "high",
                    "change": "signing files changed",
                    "reason": "possible re-sign or certificate "
                              "rotation; verify continuity before "
                              "treating as an update"})
    for perm in d["permissions_added"]:
        if perm in DANGEROUS_PERMISSIONS:
            sev.append({"level": "high",
                        "change": f"dangerous permission added: "
                                  f"{perm}",
                        "reason": "expands sensitive capability"})
        else:
            sev.append({"level": "medium",
                        "change": f"permission added: {perm}",
                        "reason": "capability surface grew"})
    if old_b.get("target_sdk") != new_b.get("target_sdk") or \
            old_b.get("min_sdk") != new_b.get("min_sdk"):
        sev.append({"level": "medium", "change": "SDK levels changed",
                    "reason": f"min {old_b.get('min_sdk')} -> "
                              f"{new_b.get('min_sdk')}, target "
                              f"{old_b.get('target_sdk')} -> "
                              f"{new_b.get('target_sdk')}"})
    nl = d["native_libs"]
    if nl["added"] or nl["removed"] or nl["changed"]:
        sev.append({"level": "medium",
                    "change": "native libraries changed",
                    "reason": f"+{len(nl['added'])} "
                              f"-{len(nl['removed'])} "
                              f"~{len(nl['changed'])}"})
    if ext.get("endpoints", {}).get("added_count") or \
            ext.get("endpoints", {}).get("removed_count"):
        sev.append({"level": "medium",
                    "change": "network endpoints changed",
                    "reason": f"+{ext['endpoints']['added_count']} "
                              f"-{ext['endpoints']['removed_count']}"})
    if ext["assets"]["changed_count"] or ext["assets"]["added_count"]:
        sev.append({"level": "low", "change": "assets changed",
                    "reason": f"+{ext['assets']['added_count']} "
                              f"~{ext['assets']['changed_count']}"})
    ext["severity"] = sev
    ext["overall_severity"] = (
        "high" if any(s["level"] == "high" for s in sev) else
        "medium" if any(s["level"] == "medium" for s in sev) else
        "low" if sev else "none")
    return ext


_IDENTITY_FIELDS = ("package", "version_code", "version_name",
                    "min_sdk", "target_sdk", "app_label")


def feature_map(report):
    """Project a compare() report into the feature-map
    artifact: added / removed / modified per dimension the
    comparison already computes (identity, permissions,
    DEX + classes, native libraries, endpoints, assets,
    resources, signing, engine). The build-noise block
    separates signing-file churn from content entry
    changes and labels that separation a heuristic."""
    old, new = report["old"], report["new"]
    d = report["diff"]
    ext = report.get("extended") or {}
    old_b = old.get("badging") or {}
    new_b = new.get("badging") or {}
    identity = {}
    for field in _IDENTITY_FIELDS:
        if field in old_b or field in new_b:
            identity[field] = {
                "old": old_b.get(field), "new": new_b.get(field),
                "changed": old_b.get(field) != new_b.get(field)}
    signing_names = (
        {s["name"] for s in d["signing_files"]["added"]}
        | {s["name"] for s in d["signing_files"]["removed"]}
        | {c["name"] for c in d["signing_files"]["changed"]})
    ent = d["entries"]
    content_changed = [e for e in ent["changed"]
                       if e not in signing_names]
    dimensions = {
        "identity": {"changed": d["identity_changed"],
                     "fields": identity},
        "permissions": {"added": d["permissions_added"],
                        "removed": d["permissions_removed"]},
        "dex": {
            "added": [x["name"] for x in d["dex"]["added"]],
            "removed": [x["name"] for x in d["dex"]["removed"]],
            "changed": [c["name"] for c in d["dex"]["changed"]],
            "totals_delta": d["dex"]["totals_delta"],
            "total_bytes_delta": d["dex"]["total_bytes_delta"]},
        "classes": ext.get("classes") or {"available": False},
        "native_libraries": {
            "added": [x["path"] for x in d["native_libs"]["added"]],
            "removed": [x["path"]
                        for x in d["native_libs"]["removed"]],
            "changed": [c["path"]
                        for c in d["native_libs"]["changed"]]},
        "endpoints": ext.get("endpoints") or {"available": False},
        "assets": ext.get("assets") or {"available": False},
        "resources": {"arsc_status": d["resources_arsc"]["status"],
                      "counts_delta": d["counts_delta"]},
        "signing": {
            "added": [s["name"] for s in d["signing_files"]["added"]],
            "removed": [s["name"]
                        for s in d["signing_files"]["removed"]],
            "changed": [c["name"]
                        for c in d["signing_files"]["changed"]]},
        "engine": ext.get("engine_versions") or {"available": False},
        "entries": {
            "added_count": ent["added_count"],
            "removed_count": ent["removed_count"],
            "changed_count": ent["changed_count"],
            "content_changed_excluding_signing": content_changed},
    }
    return {
        "tool": "nar-compare", "version": "3.0.0",
        "kind": "version-feature-map",
        "old": {"file": old.get("file"),
                "sha256": old.get("sha256")},
        "new": {"file": new.get("file"),
                "sha256": new.get("sha256")},
        "identical_files": report.get("identical_files", False),
        "similarity": ext.get("similarity"),
        "overall_severity": ext.get("overall_severity"),
        "severity": ext.get("severity", []),
        "dimensions": dimensions,
        "build_noise": {
            "policy": "heuristic: signing files (META-INF) "
                      "change on every re-sign and are counted "
                      "in their own dimension; the entries "
                      "dimension additionally reports content "
                      "changes excluding them. A re-sign can "
                      "be legitimate (certificate rotation) — "
                      "the unfiltered counts stay in "
                      "comparison.json and the signing "
                      "dimension is never hidden.",
            "signing_files_in_entry_diff": len(signing_names),
            "content_changed_excluding_signing":
                len(content_changed)},
        "notes": ext.get("notes", []),
    }


def version_diff_md(fmap):
    """Render the feature map as a human-readable Markdown
    diff. Built from the same projection as feature-map.json
    so the two artifacts cannot disagree."""
    dims = fmap["dimensions"]
    lines = [f"# Version diff: {fmap['old']['file']} → "
             f"{fmap['new']['file']}", ""]
    lines.append(f"- Old SHA-256: `{fmap['old']['sha256']}`")
    lines.append(f"- New SHA-256: `{fmap['new']['sha256']}`")
    lines.append(f"- Identical files: {fmap['identical_files']}")
    if fmap.get("similarity"):
        lines.append(
            f"- Entry similarity (identical / union): "
            f"{fmap['similarity']['entry_jaccard_identical']}")
    lines.append(f"- Overall severity: "
                 f"{fmap.get('overall_severity')}")
    lines.append("")
    idf = dims["identity"]["fields"]
    if idf:
        lines.append("## Identity")
        for field, v in idf.items():
            mark = " (changed)" if v["changed"] else ""
            lines.append(f"- {field}: {v['old']} → {v['new']}{mark}")
        lines.append("")
    perms = dims["permissions"]
    lines.append("## Permissions")
    lines.append(f"- Added ({len(perms['added'])}): "
                 f"{', '.join(perms['added']) or '—'}")
    lines.append(f"- Removed ({len(perms['removed'])}): "
                 f"{', '.join(perms['removed']) or '—'}")
    lines.append("")
    dex = dims["dex"]
    lines.append("## DEX")
    lines.append(f"- Files added: {dex['added'] or '—'}; "
                 f"removed: {dex['removed'] or '—'}; "
                 f"changed: {dex['changed'] or '—'}")
    lines.append(f"- Totals delta: {dex['totals_delta']}")
    cls = dims["classes"]
    if cls.get("available") is False:
        lines.append("- Classes: unavailable (see notes)")
    else:
        lines.append(f"- Classes: +{cls['added_count']} "
                     f"-{cls['removed_count']}")
    lines.append("")
    eps = dims["endpoints"]
    lines.append("## Endpoints")
    if eps.get("available") is False:
        lines.append("- unavailable (see notes)")
    else:
        lines.append(f"- Added ({eps['added_count']}): "
                     f"{', '.join(eps['added'][:10]) or '—'}")
        lines.append(f"- Removed ({eps['removed_count']}): "
                     f"{', '.join(eps['removed'][:10]) or '—'}")
    lines.append("")
    ast = dims["assets"]
    lines.append("## Assets")
    if ast.get("available") is False:
        lines.append("- unavailable (see notes)")
    else:
        lines.append(f"- +{ast['added_count']} "
                     f"-{ast['removed_count']} "
                     f"~{ast['changed_count']}")
    nat = dims["native_libraries"]
    lines.append("")
    lines.append("## Native libraries")
    lines.append(f"- Added: {nat['added'] or '—'}")
    lines.append(f"- Removed: {nat['removed'] or '—'}")
    lines.append(f"- Changed: {nat['changed'] or '—'}")
    sig = dims["signing"]
    lines.append("")
    lines.append("## Signing files")
    lines.append(f"- Added: {sig['added'] or '—'}; "
                 f"removed: {sig['removed'] or '—'}; "
                 f"changed: {sig['changed'] or '—'}")
    eng = dims["engine"]
    lines.append("")
    lines.append("## Engine")
    if eng.get("available") is False:
        lines.append("- unavailable (see notes)")
    else:
        lines.append(f"- changed: {eng.get('changed')}")
    if fmap["severity"]:
        lines.append("")
        lines.append("## Severity findings")
        for s in fmap["severity"]:
            lines.append(f"- [{s['level']}] {s['change']} — "
                         f"{s['reason']}")
    lines.append("")
    lines.append("## Build noise (heuristic)")
    lines.append(f"- {fmap['build_noise']['policy']}")
    lines.append(
        f"- Content entries changed (excluding signing): "
        f"{fmap['build_noise']['content_changed_excluding_signing']}")
    for note in fmap["notes"]:
        lines.append(f"- note: {note}")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(report, out_dir):
    """Write comparison.json + feature-map.json +
    version-diff.md into out_dir. Returns the three paths."""
    os.makedirs(out_dir, exist_ok=True)
    fmap = feature_map(report)
    paths = {}
    for name, payload in (
            ("comparison.json", json.dumps(report, indent=1)),
            ("feature-map.json", json.dumps(fmap, indent=1)),
            ("version-diff.md", version_diff_md(fmap))):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        paths[name] = path
    return paths


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

    ext = report.get("extended") or {}
    if ext:
        lines.append("\nExtended comparison (2.0):")
        sim = ext.get("similarity") or {}
        if sim:
            lines.append(f"  Similarity: {sim['identical_entries']}/"
                         f"{sim['total_entries_union']} entries "
                         f"byte-identical "
                         f"({sim['entry_jaccard_identical']:.0%})")
        if "classes" in ext:
            lines.append(f"  Classes: +{ext['classes']['added_count']}"
                         f" -{ext['classes']['removed_count']}")
        if "endpoints" in ext:
            lines.append(f"  Endpoints: "
                         f"+{ext['endpoints']['added_count']} "
                         f"-{ext['endpoints']['removed_count']}")
        lines.append(f"  Assets: +{ext['assets']['added_count']} "
                     f"-{ext['assets']['removed_count']} "
                     f"~{ext['assets']['changed_count']}")
        if ext.get("engine_versions", {}).get("changed"):
            lines.append(f"  Engine versions changed: "
                         f"{ext['engine_versions']['old']} -> "
                         f"{ext['engine_versions']['new']}")
        lines.append(f"  Overall severity: "
                     f"{ext.get('overall_severity', 'n/a')}")
        for s in ext.get("severity", []):
            lines.append(f"    [{s['level']}] {s['change']} — "
                         f"{s['reason']}")
        for note in ext.get("notes", []):
            lines.append(f"  note: {note}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR compare: diff two APK versions without apktool or jadx.")
    p.add_argument("old_apk", help="path to the older .apk file")
    p.add_argument("new_apk", help="path to the newer .apk file")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--out", metavar="DIR",
                   help="also write comparison.json, "
                        "feature-map.json and version-diff.md "
                        "into DIR")
    args = p.parse_args(argv)
    try:
        report = compare(args.old_apk, args.new_apk)
    except FileNotFoundError as e:
        print(f"nar-compare: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"nar-compare: cannot read file: {e}", file=sys.stderr)
        return 2
    if args.out and "error" not in report["old"] \
            and "error" not in report["new"]:
        paths = write_artifacts(report, args.out)
        if not args.json:
            for name in ("comparison.json", "feature-map.json",
                         "version-diff.md"):
                print(f"wrote {paths[name]}")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    bad = ("error" in report["old"]) or ("error" in report["new"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
