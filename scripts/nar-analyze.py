#!/usr/bin/env python3
"""nar-analyze.py: the one-command full static workup.

Given an APK, AAB, XAPK/APKM container, or OBB, runs the whole NAR
static workflow and writes ONE evidence report (Markdown + JSON):

- a doctor-lite environment note (core toolchain verdict),
- triage: identity, engines, frameworks, protections, versions,
- the nar-perms audit summary,
- the nar-strings summary (group counts and top findings),
- engine deep dives routed by what the package actually contains:
  Unity IL2CPP (nar-il2cpp), Unreal .pak listing (nar-pak),
  Godot pack (nar-godot), Flutter fingerprint (nar-flutter),
  React Native bundle (nar-rn),
- a closing Limitations and unknowns section.

Every step REUSES the bundled scripts through their --json output;
no analysis logic is duplicated here. Optional tools that are
missing degrade the matching section to an explicit note, never to
a fabricated result. Everything reported is a static observation:
this tool never runs the app and never claims runtime behavior.

Usage:
    python3 nar-analyze.py target.apk [--out DIR] [--work DIR]

The report lands in --out (default ./nar-analyze-<target name>) as
report.md and report.json. Stdlib only.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL_TIMEOUT = 1800
sys.path.insert(0, HERE)
try:
    from narlib import __version__ as NAR_VERSION
except Exception:  # narlib missing: keep the tool usable
    NAR_VERSION = "2.3.0"

# One entry per bundled-tool run, in execution order. main()
# turns this into execution-log.json (2.0 orchestrator record).
EXEC_LOG = []


def run_json_tool(script, args, timeout=TOOL_TIMEOUT):
    """Run a bundled script with --json; return (data, error)."""
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        return None, f"{script} is missing from the skill"
    cmd = [sys.executable, path] + args + ["--json"]
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "failed",
                         "duration_s": round(time.time() - started, 3)})
        return None, f"{script} did not finish within {timeout}s"
    except OSError as e:
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "failed",
                         "duration_s": round(time.time() - started, 3)})
        return None, f"{script} could not start: {e}"
    try:
        data = json.loads(proc.stdout)
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "ok",
                         "duration_s": round(time.time() - started, 3)})
        return data, None
    except ValueError:
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "failed",
                         "duration_s": round(time.time() - started, 3)})
        tail = (proc.stderr or proc.stdout or "").strip()[-300:]
        return None, f"{script} produced no JSON (exit {proc.returncode})" \
                     + (f": {tail}" if tail else "")


def run_doctor():
    path = os.path.join(HERE, "nar-doctor.sh")
    if not os.path.isfile(path):
        return None, "nar-doctor.sh is missing from the skill"
    try:
        proc = subprocess.run(["bash", path, "--json"],
                              capture_output=True, text=True, timeout=300)
        data = json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        return None, f"doctor did not run: {e}"
    checks = data.get("checks", [])
    return {
        "core_ok": data.get("core_ok"),
        "core_problems": [c["name"] for c in checks
                          if c.get("status") in ("missing", "warning")],
        "optional_missing": [c["name"] for c in checks
                             if c.get("status") == "optional-missing"],
        "checks": checks,
    }, None


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_base_apk(triage, names):
    """Choose the base APK inside a container: the one named after
    the package when known, else the largest."""
    contained = triage.get("contained_apks") or []
    if not contained:
        return None
    package = (triage.get("container_manifest") or {}).get("package")
    for item in contained:
        if package and item["name"] == f"{package}.apk":
            return item["name"]
    contained = [c for c in contained if c["name"] in names]
    if not contained:
        return None
    return max(contained, key=lambda c: c.get("size_bytes", 0))["name"]


def extract_entry(zf, name, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with zf.open(name) as src, open(dest, "wb") as dst:
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            dst.write(chunk)
    return dest


def zip_entry_flags(names):
    return {
        "il2cpp": any(n.endswith("/libil2cpp.so") or n == "libil2cpp.so"
                      for n in names),
        "flutter": any(n.endswith("/libflutter.so")
                       or n.endswith("/libapp.so") for n in names),
        # React Native routing: the contract asset name, any
        # *.jsbundle, or a top-level assets/*.bundle. Deep assets/**.bundle
        # files are Unity Addressables territory; nar-rn content-
        # validates whatever it is handed either way.
        "rn_bundle": any(n.endswith(".jsbundle")
                         or n.rsplit("/", 1)[-1]
                         in ("index.android.bundle",)
                         or (n.startswith("assets/")
                             and n.count("/") == 1
                             and n.endswith(".bundle"))
                         for n in names),
        "godot": any(n.lower().endswith(".pck")
                     or "libgodot" in n
                     or n.startswith("assets/.godot/") for n in names),
        "paks": [n for n in names if n.lower().endswith(".pak")],
        "utocs": [n for n in names if n.lower().endswith(".utoc")],
        "uassets": [n for n in names
                    if n.lower().endswith((".uasset", ".umap"))],
    }


def summarize_strings(data):
    groups = {}
    for name, group in (data.get("groups") or {}).items():
        if isinstance(group, dict):
            hits = group.get("hits") or []
            count = group.get("count", len(hits))
        elif isinstance(group, list):
            hits = group
            count = len(hits)
        else:
            hits, count = [], 0
        top = []
        for hit in hits[:5]:
            if isinstance(hit, str):
                text = hit
            elif isinstance(hit, dict):
                value = hit.get("value") or hit.get("string") or ""
                sources = hit.get("sources") or []
                text = str(value)
                if sources:
                    text += " [" + ", ".join(
                        str(s) for s in sources[:2]) + "]"
                if not text.strip():
                    text = json.dumps(hit, sort_keys=True)
            else:
                text = str(hit)
            # One clean line per hit: collapse whitespace and
            # neutralize Markdown code-span backticks so a
            # structured hit can never leak as a raw JSON blob.
            text = " ".join(text.split()).replace("`", "'")
            top.append(text[:200])
        groups[name] = {"count": count, "top": top}
    return {"total_raw_strings": data.get("total_raw_strings"),
            "unique_strings": data.get("unique_strings"),
            "sources_scanned": data.get("sources_scanned"),
            "groups": groups}


def summarize_perms(data):
    by_group = {}
    for group, items in (data.get("permissions_by_group") or {}).items():
        by_group[group] = (len(items) if isinstance(items, list)
                           else items)
    app = data.get("application") or {}
    return {
        "package": data.get("package"),
        "permission_count": data.get("permission_count"),
        "permissions_by_group": by_group,
        "dangerous_permissions": [
            p.get("name") for p in (data.get("permissions") or [])
            if isinstance(p, dict) and p.get("group") == "dangerous"
            and p.get("name")],
        "component_counts": data.get("component_counts"),
        "exported_count": data.get("exported_count"),
        "debuggable": app.get("debuggable"),
        "allow_backup": app.get("allow_backup"),
        "target_sdk": data.get("target_sdk"),
        "is_split": bool(data.get("split_name")),
    }


def _stage_cache_path(out_dir, stage):
    return os.path.join(out_dir, "cache", f"{stage}.json")


def run_cached_stage(stage, script, args, cache_key, out_dir):
    """Run one 2.0 stage with case-workspace caching.

    The cache key binds the input hash + stage + NAR version;
    a hit returns the stored document with status "cached"
    instead of re-running the tool (resume semantics)."""
    cache_path = _stage_cache_path(out_dir, stage)
    key_path = cache_path + ".key"
    if os.path.isfile(cache_path) and os.path.isfile(key_path):
        with open(key_path, encoding="utf-8") as fh:
            if fh.read().strip() == cache_key:
                with open(cache_path, encoding="utf-8") as fh:
                    EXEC_LOG.append({
                        "stage": stage, "module": script,
                        "tool": script, "tool_version": NAR_VERSION,
                        "status": "cached", "duration_s": 0.0})
                    return json.load(fh), None, True
    data, err = run_json_tool(script, args)
    if data is not None and out_dir:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with open(key_path, "w", encoding="utf-8") as fh:
            fh.write(cache_key)
    return data, err, False


def run_2_0_stages(report, apk_path, out_dir, work_dir):
    """The 2.0 module stages: fingerprint, engine fusion, DEX,
    native, network, security, assets. Each writes its
    standardized companion document into the case directory
    and a summary into the report. Failures degrade to a
    limitation line, never to a fabricated result."""
    companions = {}
    report["companions"] = companions
    if not out_dir:
        report["limitations"].append(
            "2.0 module stages skipped: no case output directory")
        return
    os.makedirs(out_dir, exist_ok=True)
    cache_key_base = sha256_of(apk_path) + "|" + NAR_VERSION

    def stage(stage_name, script, args, companion_file, summarize):
        key = hashlib.sha256(
            f"{cache_key_base}|{stage_name}".encode()).hexdigest()
        data, err, cached = run_cached_stage(
            stage_name, script, args, key, out_dir)
        if data is None:
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {err}")
            return None
        with open(os.path.join(out_dir, companion_file),
                  "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        companions[stage_name] = {"file": companion_file,
                                  "cached": cached}
        summarize(data)
        return data

    def sum_fingerprint(data):
        report["fingerprint_summary"] = {
            "properties": sorted((data.get("properties") or {}).keys())}

    def sum_engines(data):
        report["engine_verdicts"] = [
            {"engine": v["engine"], "detected": v["detected"],
             "confidence": v["confidence"], "score": v["score"],
             "version": v.get("version")}
            for v in data.get("verdicts", [])]
        report["engine_ambiguities"] = data.get("ambiguities", [])

    def sum_dex(data):
        report["dex_summary"] = {
            "totals": data.get("totals"),
            "dex_files": [{"name": d.get("name"),
                           "class_count": d.get("class_count"),
                           "kotlin": d.get("kotlin")}
                          for d in data.get("dex_files", [])
                          if "error" not in d]}

    def sum_native(data):
        report["native_summary"] = {
            "libraries": len(data.get("libraries", [])),
            "jni_libraries": len(data.get("jni_map", {})),
            "dependency_edges": sum(
                len(v) for v in
                (data.get("dependency_graph") or {}).values())}

    def sum_network(data):
        report["network_summary"] = {
            "endpoint_count": len(data.get("endpoints", [])),
            "hosts": len(data.get("hosts", [])),
            "api_hosts": data.get("api_hosts", []),
            "classification_counts": data.get(
                "classification_counts"),
            "services": [s["service"]
                         for s in data.get("services", [])],
            "network_security_config": data.get(
                "network_security_config")}

    def sum_security(data):
        report["security_summary"] = {
            "severity_counts": data.get("severity_counts"),
            "findings": len(data.get("findings", [])),
            "positive_observations": data.get(
                "positive_observations", [])}

    def sum_assets(data):
        report["assets_summary"] = {
            "total_assets": data.get("total_assets"),
            "total_bytes": data.get("total_bytes"),
            "by_category": data.get("by_category"),
            "duplicate_groups": len(data.get("duplicates", []))}

    stage("fingerprint", "nar-fingerprint.py", [apk_path],
          "fingerprint.json", sum_fingerprint)
    stage("engines", "nar-engines.py", [apk_path],
          "engines.json", sum_engines)
    dex_dir = os.path.join(out_dir, "dex")
    stage("dex", "nar-dex.py", [apk_path, "--out", dex_dir],
          "dex.json", sum_dex)
    stage("native", "nar-native.py", [apk_path],
          "native.json", sum_native)
    stage("network", "nar-network.py",
          [apk_path, "--work", os.path.join(work_dir, "network")],
          "endpoints.json", sum_network)
    stage("security", "nar-security.py", [apk_path],
          "security-findings.json", sum_security)
    stage("assets", "nar-assets.py", [apk_path],
          "assets.json", sum_assets)


def analyze(target, work_dir, out_dir=None):
    report = {"tool": "nar-analyze", "version": NAR_VERSION,
              "nar_version": NAR_VERSION,
              "target": os.path.abspath(target),
              "target_name": os.path.basename(target),
              "limitations": []}
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    report["target_sha256"] = sha256_of(target)
    report["target_size_bytes"] = os.path.getsize(target)
    os.makedirs(work_dir, exist_ok=True)

    doctor, err = run_doctor()
    report["environment"] = doctor or {"error": err}
    if err:
        report["limitations"].append(f"Environment check unavailable: {err}")
    elif doctor and not doctor["core_ok"]:
        report["limitations"].append(
            "Core toolchain is incomplete (doctor): "
            + ", ".join(doctor["core_problems"]))

    triage, err = run_json_tool("nar-triage.py", [target])
    if triage is None:
        report["fatal"] = f"triage failed: {err}"
        return report
    report["triage"] = triage
    badging = triage.get("badging") or {}
    manifest = triage.get("container_manifest") or {}
    report["identity"] = {
        "package": badging.get("package") or manifest.get("package")
                   or triage.get("obb_package"),
        "version_name": badging.get("version_name")
                        or manifest.get("version_name"),
        "version_code": badging.get("version_code")
                        or manifest.get("version_code")
                        or triage.get("obb_version_code"),
        "app_label": badging.get("app_label") or manifest.get("app_label"),
        "min_sdk": badging.get("min_sdk") or manifest.get("min_sdk"),
        "target_sdk": badging.get("target_sdk")
                      or manifest.get("target_sdk"),
        "form_factors": badging.get("form_factors") or [],
        "signature_schemes": triage.get("signature_schemes"),
        "kind": ("xapk/apkm container" if triage.get("is_container")
                 else "aab" if triage.get("is_aab")
                 else "obb" if triage.get("is_obb") else "apk"),
    }
    report["protections"] = triage.get("protections") or []

    # Resolve the APK that perms/strings/engine steps should run on.
    apk_for_steps = target
    step_notes = []
    if triage.get("is_aab"):
        step_notes.append(
            "target is an AAB bundle: permission, string, and engine"
            " steps need an APK built from it (bundletool build-apks)"
            " and were skipped")
        apk_for_steps = None
    elif triage.get("is_container"):
        with zipfile.ZipFile(target) as zf:
            names = zf.namelist()
            base = pick_base_apk(triage, names)
            if base:
                apk_for_steps = extract_entry(
                    zf, base, os.path.join(work_dir, "container", base))
                step_notes.append(
                    f"container: steps ran on the contained base APK"
                    f" {base}")
            else:
                apk_for_steps = None
                step_notes.append("container holds no triageable base"
                                  " APK; APK-level steps skipped")
            report["contained_obbs"] = [
                n for n in names if n.lower().endswith(".obb")]
    elif triage.get("is_obb"):
        step_notes.append("target is an OBB: it carries no manifest,"
                          " so the permission audit was skipped")
    report["step_notes"] = step_notes

    if apk_for_steps and not triage.get("is_obb"):
        perms, err = run_json_tool("nar-perms.py", [apk_for_steps])
        report["permissions"] = (summarize_perms(perms) if perms
                                 else {"error": err})
        if err:
            report["limitations"].append(f"Permission audit failed: {err}")
    elif triage.get("is_obb"):
        report["permissions"] = {"skipped": "OBB files have no manifest"}

    strings_target = apk_for_steps or (target if triage.get("is_obb")
                                       else None)
    if strings_target:
        strings, err = run_json_tool("nar-strings.py", [strings_target])
        report["strings"] = (summarize_strings(strings) if strings
                             else {"error": err})
        if err:
            report["limitations"].append(f"String scan failed: {err}")

    # Engine deep dives, routed by the analyzed APK's own contents.
    engines = {}
    scan_path = apk_for_steps
    if scan_path and zipfile.is_zipfile(scan_path):
        with zipfile.ZipFile(scan_path) as zf:
            flags = zip_entry_flags(zf.namelist())
            pak_sources = [(scan_path, n) for n in flags["paks"]]
        if triage.get("is_container"):
            for obb_name in report.get("contained_obbs", []):
                with zipfile.ZipFile(target) as zf:
                    obb_path = extract_entry(
                        zf, obb_name,
                        os.path.join(work_dir, "container",
                                     os.path.basename(obb_name)))
                with zipfile.ZipFile(obb_path) as ozf:
                    for n in ozf.namelist():
                        if n.lower().endswith(".pak"):
                            pak_sources.append((obb_path, n))
        if flags["il2cpp"]:
            data, err = run_json_tool(
                "nar-il2cpp.py",
                [scan_path, "--out", os.path.join(work_dir, "il2cpp")])
            engines["unity_il2cpp"] = data or {"error": err}
        if flags["flutter"]:
            data, err = run_json_tool("nar-flutter.py", [scan_path])
            engines["flutter"] = data or {"error": err}
        if flags["rn_bundle"]:
            data, err = run_json_tool(
                "nar-rn.py",
                [scan_path, "--work", os.path.join(work_dir, "rn")])
            engines["react_native"] = data or {"error": err}
        if flags["godot"]:
            data, err = run_json_tool("nar-godot.py", [scan_path])
            engines["godot"] = data or {"error": err}
        pak_reports = []
        for src_zip, entry in pak_sources[:3]:
            with zipfile.ZipFile(src_zip) as zf:
                pak_path = extract_entry(
                    zf, entry, os.path.join(
                        work_dir, "pak", os.path.basename(entry)))
            data, err = run_json_tool("nar-pak.py", [pak_path])
            if data:
                data = dict(data)
                data.pop("entries", None)  # counts/stats stay; the
                # full listing is one nar-pak run away and would bloat
                # this report
                data["contained_in"] = os.path.basename(src_zip)
                data["entry"] = entry
            pak_reports.append(data or {"error": err, "entry": entry})
        if len(pak_sources) > 3:
            report["limitations"].append(
                f"{len(pak_sources)} .pak files found; only the first"
                " 3 were listed")
        if pak_reports:
            engines["unreal_pak"] = pak_reports
        utoc_reports = []
        utoc_sources = [(scan_path, n) for n in flags["utocs"]]
        for src_zip, entry in utoc_sources[:3]:
            with zipfile.ZipFile(src_zip) as zf:
                utoc_path = extract_entry(
                    zf, entry, os.path.join(
                        work_dir, "utoc", os.path.basename(entry)))
            data, err = run_json_tool("nar-unreal.py", [utoc_path])
            containers = (data or {}).get("iostore_containers") or []
            if containers:
                summary = dict(containers[0])
                summary.pop("entries", None)  # per-chunk detail is
                # one nar-unreal run away; counts/totals stay here
                summary["contained_in"] = os.path.basename(src_zip)
                summary["entry"] = entry
                utoc_reports.append(summary)
            else:
                utoc_reports.append({"error": err or "no container"
                                     " parsed", "entry": entry})
        if len(utoc_sources) > 3:
            report["limitations"].append(
                f"{len(utoc_sources)} .utoc containers found; only"
                " the first 3 were parsed")
        if utoc_reports:
            engines["unreal_iostore"] = utoc_reports
        if flags["paks"] or flags["utocs"] or flags["uassets"]:
            # One nar-unreal run over the APK lifts the
            # UAsset-level package inspections (loose, IoStore
            # and --work-extracted pak packages) into the
            # companions; name strings are dropped here (the
            # counts stay complete) and export detail is
            # capped harder than in a direct nar-unreal run.
            data, err = run_json_tool(
                "nar-unreal.py",
                [scan_path, "--work",
                 os.path.join(work_dir, "unreal")])
            for key, out_key in (
                    ("packages", "unreal_packages"),
                    ("iostore_packages",
                     "unreal_iostore_packages"),
                    ("pak_packages", "unreal_pak_packages")):
                pkgs = (data or {}).get(key) or []
                trimmed = []
                for pkg in pkgs:
                    pkg = dict(pkg)
                    pkg.pop("names", None)
                    exps = pkg.get("exports") or []
                    if len(exps) > 25:
                        pkg["exports"] = exps[:25]
                        pkg["exports_capped"] = (
                            f"export detail capped at 25 of "
                            f"{len(exps)} in the analyze "
                            "companion; counts are complete")
                    trimmed.append(pkg)
                if trimmed:
                    engines[out_key] = trimmed
    report["engines"] = engines

    # 2.0 module stages (fingerprint / engine fusion / DEX /
    # native / network / security / assets) with case caching.
    if apk_for_steps and not triage.get("is_obb"):
        run_2_0_stages(report, apk_for_steps, out_dir, work_dir)

    # Limitations and unknowns: the honest tail of every report.
    lim = report["limitations"]
    lim.append("Static analysis only: nothing was executed, so no"
               " runtime behavior, network traffic, or server-side"
               " verdict (for example Play Integrity's) is claimed.")
    lim.append("Decompilation (jadx) is not part of this workup; see"
               " references/dex-smali-and-decompile.md for that step.")
    key_hits = ((report.get("strings") or {}).get("groups") or {}
                ).get("key_patterns", {}).get("count")
    if key_hits:
        lim.append(f"Strings: {key_hits} strings match key/token"
                   " patterns. A pattern match means a string LOOKS"
                   " like a key; it is not proof of a real secret.")
    for name, section in engines.items():
        if isinstance(section, dict) and section.get("error"):
            lim.append(f"Engine step {name} degraded: {section['error']}")
        if name == "unity_il2cpp" and isinstance(section, dict):
            dumper = section.get("dumper") or {}
            if dumper.get("error"):
                lim.append(f"IL2CPP dump degraded: {dumper['error']}")
            cpp2il = section.get("cpp2il") or {}
            if cpp2il.get("error"):
                lim.append("IL2CPP dump degraded (Cpp2IL): "
                           f"{cpp2il['error']}")
    for pak in engines.get("unreal_pak", []):
        if pak.get("encrypted_entry_count"):
            lim.append(f"Pak {pak.get('entry')}: "
                       f"{pak['encrypted_entry_count']} entries are"
                       " flagged encrypted and were not opened.")
    report["limitations"] = lim
    return report


def _fmt(value):
    return "unknown" if value in (None, "") else str(value)


def _flag_text(value, perms):
    """Render android:debuggable the way nar-perms does: an absent
    attribute is not "unknown" — the platform default is false.
    A split stub carries no value of its own."""
    if value is not None:
        return str(value)
    if perms.get("is_split"):
        return "unknown (split stub; value lives in the base APK)"
    return "false (platform default; attribute absent)"


def _backup_text(value, perms):
    """Render android:allowBackup the way nar-perms does: absent
    defaults to true below target 31, and to cloud-backup-off at
    target 31+ (device-to-device transfer still allowed)."""
    if value is not None:
        return str(value)
    if perms.get("is_split"):
        return "unknown (split stub; value lives in the base APK)"
    target = perms.get("target_sdk")
    if target is not None and target >= 31:
        return ("false for cloud backup (platform default for "
                "target 31+; attribute absent)")
    return "true (platform default; attribute absent)"


def render_md(report):
    t = report.get("triage") or {}
    ident = report.get("identity") or {}
    lines = [f"# NAR analysis: {report['target_name']}", ""]
    lines.append(f"- File: `{report['target']}`")
    lines.append(f"- SHA-256: `{report.get('target_sha256')}`")
    lines.append(f"- Size: {report.get('target_size_bytes', 0):,} bytes")
    lines.append(f"- Kind: {ident.get('kind')}")
    lines.append("- Produced by: nar-analyze.py (NAR 1.1.1), reusing"
                 " nar-doctor, nar-triage, nar-perms, nar-strings and"
                 " the engine scripts. Static analysis only.")
    env = report.get("environment") or {}
    lines += ["", "## Environment", ""]
    if env.get("error"):
        lines.append(f"Doctor unavailable: {env['error']}")
    else:
        lines.append(f"Core toolchain READY: {env.get('core_ok')}")
        if env.get("core_problems"):
            lines.append(f"Core problems: {', '.join(env['core_problems'])}")
        if env.get("optional_missing"):
            lines.append("Optional tools missing (deep dives degrade): "
                         + ", ".join(env["optional_missing"]))
    lines += ["", "## Identity", ""]
    lines.append(f"- Package: `{_fmt(ident.get('package'))}`")
    lines.append(f"- Version: {_fmt(ident.get('version_name'))}"
                 f" (code {_fmt(ident.get('version_code'))})")
    lines.append(f"- Label: {_fmt(ident.get('app_label'))}")
    lines.append(f"- SDK: min {_fmt(ident.get('min_sdk'))},"
                 f" target {_fmt(ident.get('target_sdk'))}")
    if ident.get("form_factors"):
        lines.append("- Form factors: "
                     + ", ".join(ident["form_factors"]))
    sig = ident.get("signature_schemes") or {}
    if sig:
        lines.append(f"- Signing: verifies={sig.get('verifies')},"
                     f" v1={sig.get('v1')}, v2={sig.get('v2')},"
                     f" v3={sig.get('v3')}, v3.1={sig.get('v3_1')},"
                     f" signers={sig.get('signers')}")
    for note in report.get("step_notes", []):
        lines.append(f"- Note: {note}")
    lines += ["", "## Engines and frameworks", ""]
    hints = t.get("engine_hints") or []
    if hints:
        for h in hints:
            lines.append(f"- Engine hint: {h.get('engine')}"
                         f" ({h.get('marker_count')} markers)")
    else:
        lines.append("- No engine hints from triage markers.")
    if t.get("engine_versions"):
        lines.append(f"- Engine versions: "
                     f"{json.dumps(t['engine_versions'])}")
    markers = t.get("dex_markers") or []
    for m in markers[:12]:
        lines.append(f"- DEX marker: {m.get('marker')}"
                     f" ({m.get('total_hits')} hits)")
    libs = t.get("library_versions") or {}
    if libs:
        top = list(libs.items())[:10]
        lines.append(f"- Library versions recorded: {len(libs)}"
                     f" (first: {', '.join(f'{k} {v}' for k, v in top)})")
    lines += ["", "## Protections", ""]
    protections = report.get("protections") or []
    if not protections:
        lines.append("- No protection markers found by static scan.")
    current = None
    for p in protections:
        if p.get("category_label") != current:
            current = p.get("category_label")
            lines.append(f"### {current}")
        ev = "; ".join((p.get("evidence") or [])[:2])
        lines.append(f"- {p.get('name')}"
                     f"{' (attributed)' if p.get('attributed') else ''}"
                     f": {ev}")
    lines += ["", "## Permissions audit", ""]
    perms = report.get("permissions") or {}
    if perms.get("error"):
        lines.append(f"Unavailable: {perms['error']}")
    elif perms.get("skipped"):
        lines.append(f"Skipped: {perms['skipped']}")
    else:
        lines.append(f"- Declared permissions: {perms.get('permission_count')}")
        lines.append(f"- By group: {json.dumps(perms.get('permissions_by_group'))}")
        lines.append(f"- Components: {json.dumps(perms.get('component_counts'))};"
                     f" exported: {perms.get('exported_count')}")
        lines.append(f"- debuggable: {_flag_text(perms.get('debuggable'), perms)};"
                     f" allowBackup: {_backup_text(perms.get('allow_backup'), perms)}")
    lines += ["", "## Strings scan", ""]
    strings = report.get("strings") or {}
    if strings.get("error"):
        lines.append(f"Unavailable: {strings['error']}")
    elif not strings:
        lines.append("Not run for this target kind.")
    else:
        lines.append(f"- Raw strings: {strings.get('total_raw_strings')};"
                     f" unique: {strings.get('unique_strings')};"
                     f" sources: {', '.join(strings.get('sources_scanned') or [])}")
        for name, group in (strings.get("groups") or {}).items():
            lines.append(f"### {name}: {group['count']} hits")
            for top in group["top"]:
                lines.append(f"- `{top}`")
    lines += ["", "## Engine deep dives", ""]
    engines = report.get("engines") or {}
    if not engines:
        lines.append("No engine deep dive applied to this target.")
    for name, section in engines.items():
        lines.append(f"### {name}")
        if isinstance(section, list):
            for pak in section:
                if pak.get("error"):
                    lines.append(f"- {pak.get('entry')}: {pak['error']}")
                else:
                    lines.append(
                        f"- {pak.get('entry')} (in {pak.get('contained_in')}):"
                        f" pak v{pak.get('pak_version')},"
                        f" {pak.get('entry_count')} entries,"
                        f" encrypted entries:"
                        f" {pak.get('encrypted_entry_count')},"
                        f" {pak.get('total_uncompressed_bytes')} bytes"
                        " uncompressed")
        elif section.get("error"):
            lines.append(f"- Unavailable: {section['error']}")
        elif name == "unity_il2cpp":
            meta = section.get("metadata") or {}
            summary = section.get("summary") or {}
            lines.append(f"- Metadata version: {meta.get('version')}"
                         f" (magic ok: {meta.get('magic_ok')})")
            if summary:
                basis = summary.get("method_count_basis") \
                    or "RVA-marked methods"
                lines.append(f"- Dump: {summary.get('types')} types,"
                             f" {summary.get('methods')} methods"
                             f" ({basis}); top namespaces:"
                             f" {json.dumps(summary.get('top_namespaces'))}")
            dumper = section.get("dumper") or {}
            if dumper.get("error"):
                lines.append(f"- Dumper: {dumper['error']}")
            cpp2il = section.get("cpp2il") or {}
            if cpp2il.get("error"):
                lines.append(f"- Cpp2IL: {cpp2il['error']}")
        elif name == "flutter":
            lines.append(f"- Dart: {section.get('dart_version')};"
                         f" Flutter: {section.get('flutter_version')};"
                         f" ABIs: {', '.join(section.get('abis') or [])};"
                         f" {section.get('build_mode')}")
        elif name == "react_native":
            if section.get("is_react_native") is False:
                lines.append(f"- Not React Native:"
                             f" {section.get('note') or 'no JS bundle'}")
            else:
                lines.append(f"- Engine: {section.get('engine')};"
                             f" bundle: {section.get('bundle_entry')}"
                             f" ({section.get('bundle_size_bytes')} bytes)")
                hermes = section.get("hermes") or {}
                if hermes:
                    lines.append(f"- Hermes bytecode v"
                                 f"{hermes.get('bytecode_version')},"
                                 f" {hermes.get('function_count')} functions,"
                                 f" {hermes.get('string_count')} strings")
        elif name == "godot":
            pck = section.get("pck") or {}
            if pck:
                lines.append(f"- Pack: format {pck.get('format_version')},"
                             f" engine {pck.get('engine_version')},"
                             f" files: {pck.get('file_count')},"
                             f" encrypted: {pck.get('encrypted')}")
            if section.get("note"):
                lines.append(f"- {section['note']}")
        else:
            lines.append(f"- `{json.dumps(section)[:400]}`")
    lines += ["", "## Limitations and unknowns", ""]
    for item in report.get("limitations", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR one-command full static workup: writes"
                    " report.md + report.json for an APK/AAB/XAPK/OBB.")
    p.add_argument("target", help="path to the .apk, .aab, .xapk,"
                                  " .apkm, or .obb file")
    p.add_argument("--out", metavar="DIR",
                   help="report directory (default ./nar-analyze-<name>)")
    p.add_argument("--work", metavar="DIR",
                   help="scratch directory for engine tools"
                        " (default: temp dir)")
    p.add_argument("--json", action="store_true",
                   help="also print the JSON report to stdout")
    p.add_argument("--no-html", action="store_true",
                   help="skip the offline HTML dashboard")
    p.add_argument("--no-cache", action="store_true",
                   help="ignore the case stage cache and re-run "
                        "every 2.0 stage")
    args = p.parse_args(argv)
    stem = os.path.splitext(os.path.basename(args.target))[0] or "target"
    out_dir = args.out or os.path.join(os.getcwd(), f"nar-analyze-{stem}")
    work_dir = args.work or os.path.join(
        tempfile.gettempdir(), f"nar-analyze-work-{stem}")
    if args.no_cache and os.path.isdir(os.path.join(out_dir, "cache")):
        import shutil
        shutil.rmtree(os.path.join(out_dir, "cache"))
    try:
        report = analyze(args.target, work_dir, out_dir)
    except FileNotFoundError as e:
        print(f"nar-analyze: {e}", file=sys.stderr)
        return 2
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "report.json")
    md_path = os.path.join(out_dir, "report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_md(report))
    # Case workspace record + execution log (2.0).
    case_id = "nar-" + report.get("target_sha256", "unknown")[:12]
    report["case_id"] = case_id
    stages = {}
    for entry in EXEC_LOG:
        stages[entry["stage"]] = {
            "status": entry["status"],
            "duration_s": entry["duration_s"]}
    case_doc = {
        "case_id": case_id, "nar_version": NAR_VERSION,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime()),
        "input": {"path": report.get("target"),
                  "sha256": report.get("target_sha256"),
                  "size_bytes": report.get("target_size_bytes")},
        "config": {"profile": "full"},
        "tool_versions": {"nar": NAR_VERSION,
                          "python": sys.version.split()[0]},
        "stages": stages,
    }
    with open(os.path.join(out_dir, "case.json"), "w",
              encoding="utf-8") as fh:
        json.dump(case_doc, fh, indent=2)
    exec_doc = {"tool": "nar-analyze", "case_id": case_id,
                "input_sha256": report.get("target_sha256"),
                "entries": EXEC_LOG}
    with open(os.path.join(out_dir, "execution-log.json"), "w",
              encoding="utf-8") as fh:
        json.dump(exec_doc, fh, indent=2)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    if not args.no_html:
        try:
            proc = subprocess.run(
                [sys.executable,
                 os.path.join(HERE, "nar-report.py"), out_dir],
                capture_output=True, text=True, timeout=300)
            if proc.returncode != 0:
                print(f"nar-analyze: HTML dashboard degraded: "
                      f"{proc.stderr.strip()[-200:]}",
                      file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f"nar-analyze: HTML dashboard skipped: {e}",
                  file=sys.stderr)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_md(report))
    print(f"\nReport written: {md_path} and {json_path}",
          file=sys.stderr)
    return 1 if report.get("fatal") else 0


if __name__ == "__main__":
    sys.exit(main())
