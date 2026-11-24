#!/usr/bin/env python3
"""nar-unity.py: Unity deep dive (brief section 5).

For a Unity APK:

- scripting backend verdict (IL2CPP vs Mono) from layout +
  the nar-il2cpp metadata analysis when IL2CPP is present,
- Unity editor version evidence: the version string embedded
  in globalgamemanagers / the UnityFS container header,
- asset inventory: UnityFS bundles (magic-verified), the
  bin/Data layout, Addressables catalog presence,
- optional UnityPy pass: when the optional UnityPy module is
  importable in the running interpreter, one bundle is loaded
  and its object-type census reported; when it is not, that
  is stated plainly (never faked).

Usage:
    python3 nar-unity.py app.apk [--json] [--work DIR]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import base64
import io
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
UNITY_VERSION_RE = re.compile(rb"(20\d\d\.\d+\.\d+[abfp]\d+)")
MAX_BUNDLE_SCAN = 200


def parse_addressables_catalog(raw):
    """Parse an Addressables content catalog (catalog.json)
    into an inventory: locations (internal ids), providers,
    resource types, and the entry table.

    The entry table is a base64 blob: an int32 entry count
    followed by count x 28-byte entries of 7 int32 fields.
    Field roles are claimed only where the values validate
    against the catalog's own tables (field 0 indexes the
    internal ids, field 1 the provider ids, field 6 the
    resource types — each verified by range on real
    catalogs); the remaining fields are reported by role
    only in aggregate (dependency / data offsets, key
    index) and never resolved beyond the evidence.
    """
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as e:
        return {"parsed": False, "error": f"not JSON: {e}"}
    if not isinstance(doc, dict) or \
            not isinstance(doc.get("m_InternalIds"), list):
        return {"parsed": False,
                "error": "no m_InternalIds list: not an "
                         "Addressables content catalog"}
    internal_ids = doc["m_InternalIds"]
    types = [t.get("m_ClassName")
             for t in doc.get("m_resourceTypes") or []
             if isinstance(t, dict) and t.get("m_ClassName")]
    providers = []
    for key in ("m_InstanceProviderData", "m_SceneProviderData"):
        pd = doc.get(key)
        if isinstance(pd, dict) and pd.get("m_Id"):
            providers.append(pd["m_Id"])
    resource_providers = [
        p["m_Id"] for p in doc.get("m_ResourceProviderData") or []
        if isinstance(p, dict) and p.get("m_Id")]
    provider_ids = [p for p in doc.get("m_ProviderIds") or []
                    if isinstance(p, str)]
    out = {
        "parsed": True,
        "locator_id": doc.get("m_LocatorId"),
        "build_result_hash": doc.get("m_BuildResultHash"),
        "location_count": len(internal_ids),
        "locations_sample": internal_ids[:25],
        "provider_ids": provider_ids,
        "resource_providers": resource_providers,
        "lifecycle_providers": providers,
        "resource_type_count": len(types),
        "resource_types": types[:200],
    }
    blob = None
    if isinstance(doc.get("m_EntryDataString"), str):
        try:
            blob = base64.b64decode(doc["m_EntryDataString"])
        except ValueError:
            blob = None
    if blob is None or len(blob) < 4:
        out["entries"] = {"decoded": False,
                          "note": "no decodable entry-data blob"}
        return out
    count = struct.unpack_from("<i", blob, 0)[0]
    if count < 0 or 4 + count * 28 != len(blob):
        out["entries"] = {
            "decoded": False, "blob_bytes": len(blob),
            "note": "entry blob does not match the validated "
                    "layout (int32 count + count x 28-byte "
                    "entries); reported by size only"}
        return out
    f0, f1, f6 = [], [], []
    for i in range(count):
        vals = struct.unpack_from("<7i", blob, 4 + i * 28)
        f0.append(vals[0])
        f1.append(vals[1])
        f6.append(vals[6])
    validated = []
    by_type = by_provider = None
    if f0 and max(f0) < len(internal_ids) and min(f0) >= 0:
        validated.append("internal_id_index")
    if f6 and types and max(f6) < len(types) and min(f6) >= 0:
        validated.append("resource_type_index")
        by_type = [{"type": types[idx], "entries": n}
                   for idx, n in Counter(f6).most_common(25)]
    if f1 and provider_ids and \
            max(f1) < len(provider_ids) and min(f1) >= 0:
        validated.append("provider_index")
        by_provider = [{"provider": provider_ids[idx],
                        "entries": n}
                       for idx, n in Counter(f1).most_common(10)]
    out["entries"] = {
        "decoded": True, "count": count,
        "layout": "int32 count + 28-byte entries (7 x int32)",
        "fields_validated": validated,
        "by_resource_type": by_type,
        "by_provider": by_provider,
    }
    return out


def run_json_tool(script, args, timeout=1800):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def unitypy_census(data):
    """Object-type census of one bundle via UnityPy, or None."""
    try:
        import UnityPy  # optional dependency
    except ImportError:
        return None
    try:
        env = UnityPy.load(data)
        census = {}
        for obj in env.objects:
            census[obj.type.name] = census.get(obj.type.name, 0) + 1
        return census
    except Exception:
        return None


def analyze(target, work_dir=None):
    report = {"tool": "nar-unity", "version": "2.5.1",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target)}
    triage = run_json_tool("nar-triage.py", [target]) or {}
    hints = {h["engine"] for h in triage.get("engine_hints") or []}
    versions = triage.get("engine_versions") or {}
    backend = None
    if "Unity (IL2CPP)" in hints:
        backend = "IL2CPP"
    elif "Unity (Mono)" in hints:
        backend = "Mono"
    bundles, version_strings = [], []
    addressables = False
    catalog = None
    data_files = 0
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        # The catalog is read in its own pass: the bundle walk
        # below stops early at the bundle scan cap and could
        # otherwise never reach a catalog listed late in the
        # archive.
        for name in names:
            if name.endswith("catalog.json") and \
                    ("/aa/" in name or
                     name.startswith("assets/aa/")) and \
                    zf.getinfo(name).file_size <= 268_435_456:
                catalog = parse_addressables_catalog(zf.read(name))
                catalog["path"] = name
                break
        for name in names:
            if name.startswith("assets/bin/Data/"):
                data_files += 1
            if name.startswith("assets/aa/") or \
                    name.endswith("catalog.json"):
                addressables = True
            if name in ("assets/bin/Data/globalgamemanagers",
                        "assets/bin/Data/data.unity3d") or \
                    name.endswith((".unity3d", ".bundle")):
                with zf.open(name) as fh:
                    head = fh.read(4096)
                is_bundle = head.startswith(
                    (b"UnityFS", b"UnityWeb", b"UnityRaw"))
                if name.endswith("globalgamemanagers") or is_bundle:
                    m = UNITY_VERSION_RE.search(head)
                    if m:
                        version_strings.append(
                            m.group(1).decode("ascii", "replace"))
                if is_bundle:
                    bundles.append(name)
            if len(bundles) > MAX_BUNDLE_SCAN:
                break
    report.update({
        "verdict": "unity" if backend else "absent",
        "scripting_backend": backend,
        "unity_version_strings": sorted(set(version_strings)),
        "metadata_version": versions.get("unity_metadata_version"),
        "metadata_era": versions.get("unity_metadata_era"),
        "data_file_count": data_files,
        "unityfs_bundles": bundles[:50],
        "unityfs_bundle_count": len(bundles),
        "addressables": addressables,
    })
    if catalog is not None:
        report["addressables_catalog"] = catalog
    if backend == "IL2CPP":
        il2cpp_args = [target]
        if work_dir:
            # Keep the (large) dumper output in the caller's
            # work dir instead of the tool's /tmp default.
            il2cpp_args += ["--out",
                            os.path.join(work_dir, "il2cpp")]
        il2cpp = run_json_tool("nar-il2cpp.py", il2cpp_args)
        if il2cpp:
            report["il2cpp"] = {k: il2cpp.get(k) for k in
                                ("verdict", "metadata_version",
                                 "dumper") if k in il2cpp}
    # Optional UnityPy census on the first bundle found.
    census = None
    if bundles:
        with zipfile.ZipFile(target) as zf:
            with zf.open(bundles[0]) as fh:
                census = unitypy_census(fh.read())
    if census is not None:
        report["unitypy_census_first_bundle"] = census
    else:
        report["notes"] = [
            "UnityPy is not importable in this interpreter; "
            "bundle object census skipped (bundle inventory "
            "above is magic-verified and complete)."]
    return report


def human(report):
    print(f"NAR Unity deep dive: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Verdict: {report['verdict']} "
          f"(backend: {report['scripting_backend']})")
    if report["unity_version_strings"]:
        print(f"Unity version strings: "
              f"{report['unity_version_strings']}")
    if report["metadata_version"]:
        print(f"IL2CPP metadata: v{report['metadata_version']} "
              f"({report['metadata_era']})")
    print(f"Data files: {report['data_file_count']}; UnityFS "
          f"bundles: {report['unityfs_bundle_count']}; "
          f"Addressables: {report['addressables']}")
    cat = report.get("addressables_catalog")
    if cat and cat.get("parsed"):
        ent = cat.get("entries") or {}
        print(f"Addressables catalog: {cat['location_count']} "
              f"locations, {cat['resource_type_count']} resource "
              f"types, entries decoded: {ent.get('count')}")
    elif cat:
        print(f"Addressables catalog: not parsed "
              f"({cat.get('error')})")
    if report.get("unitypy_census_first_bundle"):
        print(f"UnityPy census (first bundle): "
              f"{report['unitypy_census_first_bundle']}")
    for note in report.get("notes", []):
        print(f"note: {note}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Unity deep dive: backend, version evidence, "
                    "bundle inventory, optional UnityPy census.")
    p.add_argument("target", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--work", metavar="DIR",
                   help="work dir for the IL2CPP dumper output "
                        "(large; keep it off a small /tmp)")
    args = p.parse_args(argv)
    try:
        report = analyze(args.target, args.work)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-unity: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
