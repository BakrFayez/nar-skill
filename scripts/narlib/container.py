"""Container detection and split-set resolution.

One shared home for the container logic that used to live in
pieces inside nar-triage (container manifest parsing) and
nar-analyze (base-APK selection, contained extraction). Every
module that opens a target resolves it through here first:

- :func:`detect_container` classifies a file by CONTENT
  (ZIP member inspection), with the extension only as a
  tie-breaker: APK / AAB / APKS / XAPK / APKM / OBB / plain
  ZIP wrapper / plain APK / unknown.
- :func:`pick_base_apk` is the ONE base-selection rule:
  the entry named after the container file, else the entry
  named after the manifest package, else a canonical base
  name (base-master.apk / base.apk), else the largest
  non-config APK (else the largest APK).
- :func:`resolve_target` turns a target path into a
  :class:`ResolvedTarget`: the base APK (extracted through
  :mod:`narlib.safearchive` under the shared budget when it
  lives inside a container), the split APKs, OBBs beside the
  target or inside the container, and the ordered archive
  roots the asset/native stages scan (base first, then
  splits). Nested containers recurse (ZIP -> XAPK -> APK)
  up to ``MAX_CONTAINER_DEPTH`` levels. Split merging is
  the caller's choice: with ``merge_splits=False`` the
  splits are recorded in ``split_skipped`` and the roots
  carry the base alone (the pre-3.0 behaviour).
- A LOOSE split set — a base APK handed over as a bare file
  with its split APKs sitting beside it in the same
  directory — is assembled by sibling discovery inside
  :func:`resolve_target` (field round F-01): set membership
  is proven, never assumed (the sibling's package, read
  from its binary manifest, must equal the base's, and the
  sibling must declare itself a split, carry a split-shaped
  name, or the base must carry bundle split evidence).
  :func:`resolve_directory` resolves a directory holding
  such a set the same way. Either way the outcome rides
  ``ResolvedTarget.split_set`` so consumers can tell a
  merged set from a base-only run and an incomplete set
  from a complete one.
- :func:`inventory_duplicates` is the duplicate/delta
  detection across a set of archives: identical member
  bytes are reported once, with every location.

Extraction never bypasses safearchive: traversal entries,
symlinks, bombs and oversized members are refused there and
surface here as ``split_skipped`` / rejection records with
named reasons — nothing is silently dropped.

Part of NAR (Nirous Android Reversing).
"""
import hashlib
import json
import os
import re
import tempfile
import zipfile

from .budget import ResourceBudget
from .safearchive import (MEMBER_READ_CAP_BYTES, raw_entry_name,
                          read_member_capped, safe_extract)

#: Kinds that are containers of APKs (a resolution extracts a
#: base APK out of them). "aab" is a bundle, not an APK
#: container: its modules are not standalone APK files, so
#: resolution keeps the bundle itself as the base.
CONTAINER_KINDS = ("xapk", "apkm", "apks", "zip")
ALL_KINDS = ("apk", "aab", "apks", "xapk", "apkm", "obb",
             "zip", "unknown")

#: Nested-container recursion ceiling (ZIP -> XAPK -> APK
#: is depth 2; the ceiling leaves one level of headroom).
MAX_CONTAINER_DEPTH = 3

#: Default per-member cap for duplicate inventory hashing:
#: a member larger than this is skipped-and-noted, never
#: materialized whole just to hash it.
DUPLICATE_MEMBER_CAP_BYTES = 256 * 1024 * 1024

#: Per-member cap for the container manifest read: the
#: manifest member is materialized in memory, so it goes
#: through safearchive's capped reader under this ceiling
#: (the same MEMBER_READ_CAP_BYTES policy, not a parallel
#: one). Resolution additionally tightens it to the shared
#: budget's per-member cap when that is smaller. Read at
#: call time so tests can patch it.
MANIFEST_READ_CAP_BYTES = MEMBER_READ_CAP_BYTES

#: Environment variable that flips the DEFAULT of
#: resolve_target's merge_splits when a caller does not pass
#: it explicitly. nar-analyze sets it from its
#: --no-merge-splits flag so the stage tools it launches as
#: subprocesses (which resolve the target through here with
#: the default) honour the same choice; it is also the
#: standalone opt-out for tools that take no such flag.
NO_MERGE_ENV_VAR = "NAR_NO_MERGE_SPLITS"


def _merge_splits_default():
    return os.environ.get(NO_MERGE_ENV_VAR, "").strip().lower() \
        not in ("1", "true", "yes", "on")


_SPLIT_CONFIG_RE = re.compile(r"(^|[._-])config[._-]|^split[._-]",
                              re.IGNORECASE)
_ABI_TOKENS = ("armeabi-v7a", "armeabi_v7a", "arm64-v8a",
               "arm64_v8a", "x86_64", "x86", "armeabi")
_DENSITY_TOKENS = ("xxxhdpi", "xxhdpi", "xhdpi", "hdpi",
                   "mdpi", "ldpi", "tvdpi", "nodpi")


def _traversal_name(name):
    """True for absolute or '..' entry names (the nar-triage
    rule, shared): such entries are never extractable."""
    if name.startswith(("/", "\\")):
        return True
    parts = name.replace("\\", "/").split("/")
    return ".." in parts


def _manifest_and_refusal(zf, cap_bytes):
    """(info, refusal) for a container's manifest.json.

    The member is read through safearchive's
    :func:`read_member_capped` under ``cap_bytes``: the
    declared size is checked BEFORE decompression and the
    streamed count again while reading, so an oversized
    manifest is never materialized whole. ``refusal`` is
    the capped reader's named reason when the member
    exceeds the cap or is unreadable/corrupt, else None;
    ``info`` is the parsed identity dict or None (absent,
    unreadable, over-cap or non-dict manifest)."""
    if "manifest.json" not in zf.namelist():
        return None, None
    try:
        raw = read_member_capped(zf, "manifest.json", cap_bytes)
    except ValueError as e:
        # The capped reader's named failure channel is
        # ValueError: the cap (declared or streamed size
        # over the ceiling) or an unreadable/corrupt member
        # (NF-02). Either way the reason is recorded.
        return None, str(e)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return None, None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None, None
    if not isinstance(data, dict):
        return None, None
    info = {}
    for src, dst in (("xapk_version", "xapk_version"),
                     ("package_name", "package"),
                     ("name", "app_label"),
                     ("version_code", "version_code"),
                     ("version_name", "version_name"),
                     ("min_sdk_version", "min_sdk"),
                     ("target_sdk_version", "target_sdk"),
                     ("total_size", "total_size")):
        if data.get(src) is not None:
            info[dst] = data[src]
    if isinstance(data.get("permissions"), list):
        info["permissions"] = sorted(
            {str(p) for p in data["permissions"]})
    if isinstance(data.get("split_configs"), list):
        info["split_configs"] = [str(s)
                                 for s in data["split_configs"]]
    splits = []
    if isinstance(data.get("split_apks"), list):
        for entry in data["split_apks"]:
            if isinstance(entry, dict) and entry.get("file"):
                splits.append({"file": str(entry["file"]),
                               "id": str(entry.get("id", ""))})
    if splits:
        info["split_apks"] = splits
    return info, None


def container_manifest_of(zf, cap_bytes=None):
    """Identity from an XAPK/APKM container's manifest.json.

    Moved verbatim from nar-triage (which re-exports it):
    package_name, version, SDK levels, permissions,
    split_configs and split_apks ({file, id}) entries.
    Returns a dict (possibly partial) or None. The member
    is read through safearchive's capped reader under
    ``cap_bytes`` (default MANIFEST_READ_CAP_BYTES): a
    manifest over the cap is refused (None), never
    materialized whole (certification A1-05)."""
    if cap_bytes is None:
        cap_bytes = MANIFEST_READ_CAP_BYTES
    info, _refusal = _manifest_and_refusal(zf, cap_bytes)
    return info


def _zip_names(path):
    """Member names of a ZIP-family file, or None."""
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return None


def detect_container(path):
    """Classify a target file by content, extension second.

    Returns one of ALL_KINDS. Content wins: a ``.zip`` file
    holding a manifest.json + APK set is an XAPK-style
    container, and a ``.xapk`` file holding a single plain
    APK layout is an APK."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".obb":
        return "obb"
    names = _zip_names(path)
    if names is None:
        return "unknown"
    lower = [n.lower() for n in names]
    apk_members = [n for n in lower if n.endswith(".apk")]
    has_manifest_json = "manifest.json" in lower
    # Bundletool .apks: toc.pb plus split APKs (usually under
    # splits/), no XAPK-style manifest.json identity.
    if "toc.pb" in lower and apk_members:
        return "apks"
    if has_manifest_json and apk_members:
        # XAPK and APKM share this shape; the extension is
        # the only honest distinguisher.
        return "apkm" if ext == ".apkm" else "xapk"
    # AAB: bundle modules (base/manifest, base/dex, ...).
    if any(n.startswith("base/manifest/") for n in lower) or \
            "base/resources.pb" in lower or ext == ".aab":
        if ext == ".aab" or any(
                n.startswith("base/") for n in lower):
            return "aab"
    # Plain APK layout.
    if "androidmanifest.xml" in lower and any(
            n.rsplit("/", 1)[-1].startswith("classes")
            and n.endswith(".dex") for n in lower):
        return "apk"
    if "androidmanifest.xml" in lower and \
            "resources.arsc" in lower:
        return "apk"
    if apk_members:
        # APKs inside a ZIP with no container manifest:
        # a plain ZIP wrapper around an APK set.
        return "zip"
    if ext in (".xapk", ".apkm", ".apks"):
        return ext[1:]
    if ext == ".apk":
        return "apk"
    if ext == ".aab":
        return "aab"
    if ext == ".zip":
        return "zip"
    return "unknown"


def is_container_kind(kind):
    return kind in CONTAINER_KINDS


def split_kind(entry_name):
    """Classify one contained APK entry: base / config ABI /
    config density / config locale / feature / split."""
    base = os.path.basename(entry_name).lower()
    if base in ("base.apk", "base-master.apk"):
        return "base"
    low = base
    for abi in _ABI_TOKENS:
        if abi in low:
            return "config-abi"
    for dens in _DENSITY_TOKENS:
        if dens in low:
            return "config-density"
    if "config." in low or "config_" in low:
        # config.<lang/region> and remaining config splits.
        return "config-locale"
    if low.startswith("split_") or "_feature" in low or \
            low.startswith("feature"):
        return "feature"
    return "split"


def pick_base_apk(contained, package=None, container_stem=None):
    """The ONE base-APK selection rule (extracted from
    nar-analyze's pick_base_apk, which now delegates here).

    ``contained`` is a list of {"name", "size_bytes"} dicts.
    Order: (1) entry named after the container file's stem,
    (2) entry named after the manifest package, (3) a
    canonical base name (base-master.apk / base.apk),
    (4) the largest non-config APK, else the largest APK.
    Returns the entry name or None."""
    if not contained:
        return None
    names = [c["name"] for c in contained]
    for wanted in (container_stem, package):
        if not wanted:
            continue
        target = f"{wanted}.apk"
        for item in contained:
            if item["name"] == target:
                return item["name"]
        for item in contained:
            if os.path.basename(item["name"]) == target:
                return item["name"]
    for item in contained:
        if os.path.basename(item["name"]) in (
                "base-master.apk", "base.apk"):
            return item["name"]
    non_config = [c for c in contained
                  if not _SPLIT_CONFIG_RE.search(
                      os.path.basename(c["name"]))]
    pool = non_config or contained
    return max(pool, key=lambda c: c.get("size_bytes", 0))["name"]


class ResolvedTarget:
    """The resolution of one target path.

    Fields: ``input_path`` / ``input_kind`` (the original
    input), ``base`` (path of the base APK on disk — the
    input itself for a plain APK, an extracted file for a
    container), ``base_entry`` (container entry the base
    came from, or None), ``splits`` (each {path, name, kind,
    source_entry}), ``obbs`` (each {path, name, source}),
    ``assets_roots`` / ``native_roots`` (ordered archive
    paths: base first, then merged splits), ``splits_merged``
    and ``split_skipped`` ({name, reason} records),
    ``is_container``, and ``split_set`` (the loose-split-set
    record for sibling/directory resolutions: detected /
    resolution / base evidence / members / merged /
    complete, or None when no loose set was detected).
    ``cleanup()`` removes the extraction directory (a no-op
    for plain inputs)."""

    def __init__(self, input_path, input_kind):
        self.input_path = input_path
        self.input_kind = input_kind
        self.base = input_path
        self.base_entry = None
        self.splits = []
        self.obbs = []
        self.assets_roots = []
        self.native_roots = []
        self.splits_merged = []
        self.split_skipped = []
        self.is_container = False
        self.package = None
        self.split_set = None
        self._cleanup_dirs = []

    def container_block(self):
        """The `container` report block consumers embed."""
        block = {
            "input_kind": self.input_kind,
            "base": os.path.basename(self.base)
            if self.base else None,
            "base_entry": self.base_entry,
            "splits_merged": list(self.splits_merged),
            "split_skipped": list(self.split_skipped),
            "obbs": [o["name"] for o in self.obbs],
        }
        if self.split_set is not None:
            block["split_set"] = self.split_set
        return block

    def cleanup(self):
        import shutil
        for d in self._cleanup_dirs:
            shutil.rmtree(d, ignore_errors=True)
        self._cleanup_dirs = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False


def _beside_obbs(input_path, package=None):
    """OBB files sitting beside the target file: files in
    the same directory named like an OBB for this package
    (main./patch.<version>.<package>.obb), plus any other
    .obb file beside a container input (its payload set)."""
    out = []
    directory = os.path.dirname(os.path.abspath(input_path))
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return out
    self_abs = os.path.abspath(input_path)
    for name in entries:
        if not name.lower().endswith(".obb"):
            continue
        full = os.path.join(directory, name)
        if os.path.abspath(full) == self_abs:
            continue
        if package and f".{package}." not in name and \
                not name.startswith(("main.", "patch.")):
            continue
        out.append({"path": full, "name": name,
                    "source": "beside-target"})
    return out


_perms_mod = None


def _load_perms():
    """nar-perms.py loaded as a module (the chains.py
    pattern): its parse_axml is the tree's proven binary
    manifest parser, and set-membership checks need the
    package / split attributes it extracts."""
    global _perms_mod
    if _perms_mod is None:
        import importlib.util
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..",
            "nar-perms.py")
        spec = importlib.util.spec_from_file_location(
            "nar_perms_for_container", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _perms_mod = mod
    return _perms_mod


def apk_manifest_identity(path):
    """(package, split_name) declared by an APK's binary
    AndroidManifest.xml, or (None, None) when either cannot
    be read. Fail-closed by design: sibling-split discovery
    treats an unreadable manifest as NO identity, never as
    a match. The manifest member is read through
    safearchive's capped reader under the same ceiling as
    container manifests."""
    try:
        with zipfile.ZipFile(path) as zf:
            try:
                raw = read_member_capped(
                    zf, "AndroidManifest.xml",
                    MANIFEST_READ_CAP_BYTES)
            except (ValueError, KeyError, OSError,
                    RuntimeError, zipfile.BadZipFile):
                return None, None
    except (zipfile.BadZipFile, OSError):
        return None, None
    try:
        root = _load_perms().parse_axml(raw)
    except Exception:
        return None, None
    attrs = getattr(root, "attrs", None) or {}
    package = attrs.get("package")
    split = attrs.get("split") or attrs.get("android:split")
    return (str(package) if package else None,
            str(split) if split else None)


def bundle_split_evidence(path):
    """Base-carried split-set evidence in an APK's own
    member list: the bundletool stamp (stamp-cert-sha256)
    and the splits manifest resources (res/xml/splits*) —
    the same signals nar-triage records as
    bundle_split_evidence. Empty list when the file is not
    a readable ZIP or carries neither marker."""
    names = _zip_names(path)
    if not names:
        return []
    return sorted(n for n in names
                  if n == "stamp-cert-sha256"
                  or n.startswith("res/xml/splits"))


def _sibling_candidates(directory, self_abs):
    """APK files sitting beside a target file (never the
    target itself), name-sorted for deterministic output."""
    out = []
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in entries:
        if not name.lower().endswith(".apk"):
            continue
        full = os.path.join(directory, name)
        if os.path.abspath(full) == self_abs:
            continue
        if os.path.isfile(full):
            out.append((name, full))
    return out


def _discover_sibling_splits(resolved, path, merge_splits):
    """Assemble the loose split set a lone base APK belongs
    to, from the APK files beside it (field round F-01).

    Membership is proven per candidate: the candidate's
    package (from its binary manifest) must equal the
    base's, AND at least one split signal must hold — the
    candidate declares a split name in its manifest, its
    file name is split-shaped (config.* / split_* / an ABI,
    density or feature token), or the base itself carries
    bundle split evidence. A candidate that fails the
    package check is never merged; when the base carries
    evidence, the rejection is recorded so the case can
    say why the set is incomplete. When nothing is
    accepted and the base carries no evidence, the target
    is an ordinary lone APK and the resolution is left
    untouched (split_set stays None)."""
    directory = os.path.dirname(os.path.abspath(path))
    candidates = _sibling_candidates(directory,
                                     os.path.abspath(path))
    if not candidates:
        return
    evidence = bundle_split_evidence(path)
    base_package, _base_split = apk_manifest_identity(path)
    accepted, skipped = [], []
    for name, full in candidates:
        package, split_name = apk_manifest_identity(full)
        if base_package is None or package is None \
                or package != base_package:
            if evidence:
                if package and base_package:
                    reason = ("sibling candidate not merged: "
                              "its package identity does not "
                              "match the base APK")
                else:
                    reason = ("sibling candidate not merged: "
                              "package identity could not be "
                              "verified")
                skipped.append({"name": name,
                                "reason": reason})
            continue
        name_shaped = split_kind(name) != "split" or \
            bool(_SPLIT_CONFIG_RE.search(name))
        if split_name or name_shaped or evidence:
            accepted.append({
                "path": full, "name": name,
                "kind": split_kind(name),
                "source_entry": name,
                "source": "sibling-file"})
        elif evidence:
            skipped.append({
                "name": name,
                "reason": "sibling candidate not merged: "
                          "same package but no split "
                          "declaration or split-shaped name"})
    if not accepted and not evidence:
        return
    resolved.base_entry = os.path.basename(path)
    resolved.split_set = {
        "detected": True,
        "resolution": "sibling-files",
        "directory": directory,
        "base": os.path.basename(path),
        "package": base_package,
        "base_evidence": evidence,
        "members": [{"name": s["name"], "kind": s["kind"],
                     "source": s["source"]}
                    for s in accepted],
        "skipped": skipped,
        "merged": bool(merge_splits and accepted),
        "complete": bool(merge_splits and accepted),
    }
    if merge_splits:
        for s in accepted:
            resolved.splits.append(s)
            resolved.splits_merged.append({
                "name": s["name"], "kind": s["kind"],
                "source_entry": s["source_entry"]})
        if accepted:
            resolved.assets_roots = [resolved.base] + \
                [s["path"] for s in accepted]
            resolved.native_roots = list(resolved.assets_roots)
    else:
        for s in accepted:
            resolved.split_skipped.append({
                "name": s["name"],
                "reason": "split merge disabled "
                          "(--no-merge-splits)"})


def resolve_directory(path, merge_splits=None, budget=None):
    """Resolve a DIRECTORY holding a loose split set.

    The directory is the user's explicit statement that its
    APK files form one set: the base is picked with the
    shared :func:`pick_base_apk` rule (the set package is
    the package most members declare), and every other APK
    whose package matches the base's is a split. A member
    whose package provably differs is recorded in
    ``split_skipped`` instead of being merged. Returns None
    when the directory holds no APK at all. No extraction
    happens: the members already live on disk."""
    if merge_splits is None:
        merge_splits = _merge_splits_default()
    directory = os.path.abspath(path)
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return None
    members = []
    for name in entries:
        full = os.path.join(directory, name)
        if name.lower().endswith(".apk") \
                and os.path.isfile(full):
            members.append({"name": name, "path": full,
                            "size_bytes": os.path.getsize(full)})
    if not members:
        return None
    packages = {m["name"]: apk_manifest_identity(m["path"])[0]
                for m in members}
    known = [p for p in packages.values() if p]
    set_package = None
    if known:
        set_package = max(sorted(set(known)), key=known.count)
    base_entry = pick_base_apk(
        [{"name": m["name"], "size_bytes": m["size_bytes"]}
         for m in members], package=set_package)
    base_member = next(m for m in members
                       if m["name"] == base_entry)
    resolved = ResolvedTarget(directory, "directory")
    resolved.base = base_member["path"]
    resolved.base_entry = base_entry
    resolved.package = set_package
    splits, skipped = [], []
    for m in members:
        if m["name"] == base_entry:
            continue
        pkg = packages[m["name"]]
        if set_package is not None and pkg is not None \
                and pkg != set_package:
            rec = {"name": m["name"],
                   "reason": "not merged: package identity "
                             "does not match the set's base "
                             "APK"}
            skipped.append(rec)
            resolved.split_skipped.append(rec)
            continue
        splits.append(m)
    if merge_splits:
        for m in splits:
            kind = split_kind(m["name"])
            resolved.splits.append({
                "path": m["path"], "name": m["name"],
                "kind": kind, "source_entry": m["name"],
                "source": "directory"})
            resolved.splits_merged.append({
                "name": m["name"], "kind": kind,
                "source_entry": m["name"]})
        resolved.assets_roots = [resolved.base] + \
            [s["path"] for s in resolved.splits]
        resolved.native_roots = list(resolved.assets_roots)
    else:
        resolved.assets_roots = [resolved.base]
        resolved.native_roots = [resolved.base]
        for m in splits:
            resolved.split_skipped.append({
                "name": m["name"],
                "reason": "split merge disabled "
                          "(--no-merge-splits)"})
    if len(members) > 1:
        resolved.split_set = {
            "detected": True,
            "resolution": "directory",
            "directory": directory,
            "base": base_entry,
            "package": set_package,
            "base_evidence": bundle_split_evidence(
                base_member["path"]),
            "members": [{"name": s["name"],
                         "kind": s["kind"],
                         "source": s["source"]}
                        for s in resolved.splits],
            "skipped": skipped,
            "merged": bool(merge_splits and resolved.splits),
            "complete": bool(merge_splits),
        }
    resolved.obbs = _beside_obbs(base_member["path"],
                                 set_package)
    return resolved


def resolved_set_sha256(resolved):
    """SHA-256 identity of a resolved set: the digest of
    the ordered (name, size, sha256) records of the base
    and every merged split. Used to key a case whose input
    is a set (a directory) rather than one file, so the
    stage-cache keys verify against the recorded input
    hash exactly as they do for a single file."""
    digest = hashlib.sha256()
    paths = [resolved.base] + [s["path"]
                               for s in resolved.splits]
    for p in paths:
        member = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                member.update(chunk)
        digest.update(
            os.path.basename(p).encode("utf-8", "replace"))
        digest.update(b"\0")
        digest.update(str(os.path.getsize(p)).encode())
        digest.update(b"\0")
        digest.update(member.hexdigest().encode())
        digest.update(b"\n")
    return digest.hexdigest()


def resolve_target(path, merge_splits=None, budget=None,
                   work_dir=None, _depth=0):
    """Resolve a target path to a :class:`ResolvedTarget`.

    All extraction goes through safearchive under the
    shared budget (a ResourceBudget or a safearchive limits
    dict). Nested containers recurse up to
    MAX_CONTAINER_DEPTH. With ``merge_splits=False`` the
    base alone is resolved and every split is recorded in
    ``split_skipped`` (the pre-3.0 behaviour). With
    ``merge_splits=None`` (the default) the choice falls
    back to the NAR_NO_MERGE_SPLITS environment variable
    (see NO_MERGE_ENV_VAR), then to merging. A plain APK
    additionally goes through sibling-split discovery: a
    loose split set handed over as a bare base file is
    assembled from the APKs beside it."""
    if merge_splits is None:
        merge_splits = _merge_splits_default()
    budget = ResourceBudget.from_safearchive_limits(budget)
    resolved = ResolvedTarget(os.path.abspath(path),
                              detect_container(path))
    kind = resolved.input_kind
    if kind not in CONTAINER_KINDS:
        resolved.base = os.path.abspath(path)
        if kind in ("apk", "aab"):
            resolved.assets_roots = [resolved.base]
            resolved.native_roots = [resolved.base]
        elif kind == "obb":
            resolved.assets_roots = [resolved.base]
        resolved.obbs = _beside_obbs(path)
        if kind == "apk":
            _discover_sibling_splits(resolved, path,
                                     merge_splits)
        return resolved

    resolved.is_container = True
    # --- inventory the container (no extraction yet) -------
    # Inventory names are the RAW names as stored in the
    # archive (raw_entry_name): every record derived from
    # them (contained, refused/split_skipped, base_entry) is
    # evidence and must cite the stored name, and the raw
    # keys are what safearchive's extracted/rejected maps
    # are keyed by, so lookups below match on every
    # platform. Decisions (suffix, traversal) are made on
    # the normalised info.filename, unchanged.
    manifest_cap = min(budget.max_file_bytes,
                       MANIFEST_READ_CAP_BYTES)
    with zipfile.ZipFile(path) as zf:
        infos = {raw_entry_name(i): i for i in zf.infolist()}
        names = list(infos)
        manifest, manifest_refusal = _manifest_and_refusal(
            zf, manifest_cap)
    if manifest_refusal:
        # An over-cap manifest is refused, never silently
        # dropped: the refusal rides the resolution's named
        # skipped records and the identity falls back to the
        # no-manifest rules below.
        resolved.split_skipped.append({
            "name": "manifest.json",
            "reason": f"container manifest refused: "
                      f"{manifest_refusal}"})
    package = (manifest or {}).get("package")
    resolved.package = package
    contained, refused = [], []
    for n in names:
        info = infos[n]
        if not info.filename.lower().endswith(".apk"):
            continue
        if _traversal_name(info.filename):
            refused.append({"name": n,
                            "reason": "entry name is absolute "
                                      "or traverses outside "
                                      "the extraction root"})
        else:
            contained.append({"name": n,
                              "size_bytes": info.file_size})
    contained.sort(key=lambda c: c["name"])
    stem = os.path.splitext(os.path.basename(path))[0]
    base_entry = pick_base_apk(contained, package=package,
                               container_stem=stem)
    resolved.base_entry = base_entry
    for rec in refused:
        resolved.split_skipped.append(rec)
    if base_entry is None and _depth < MAX_CONTAINER_DEPTH:
        # No direct APK members, but a nested container member
        # (ZIP -> XAPK -> APK): extract the largest container
        # member through safearchive and resolve IT; this
        # level's records ride along.
        nested = [{"name": n, "size_bytes": infos[n].file_size}
                  for n in names
                  if infos[n].filename.lower().endswith(
                      (".xapk", ".apkm", ".apks", ".zip"))
                  and not _traversal_name(infos[n].filename)]
        if nested:
            nested.sort(key=lambda c: c["name"])
            inner_entry = max(
                nested, key=lambda c: c["size_bytes"])["name"]
            if work_dir:
                os.makedirs(work_dir, exist_ok=True)
                extract_root = work_dir
            else:
                extract_root = tempfile.mkdtemp(
                    prefix="nar-container-")
                resolved._cleanup_dirs.append(extract_root)
            report0 = safe_extract(path, extract_root, budget)
            got = {e["entry"]: e["path"]
                   for e in report0["extracted"]}
            if inner_entry in got:
                inner = resolve_target(
                    got[inner_entry], merge_splits=merge_splits,
                    budget=budget, _depth=_depth + 1)
                resolved._cleanup_dirs.extend(
                    inner._cleanup_dirs)
                inner._cleanup_dirs = []
                resolved.base = inner.base
                resolved.base_entry = inner.base_entry
                resolved.splits = inner.splits
                resolved.splits_merged = inner.splits_merged
                resolved.split_skipped.extend(
                    inner.split_skipped)
                resolved.obbs = inner.obbs + \
                    _beside_obbs(path, package)
                resolved.assets_roots = inner.assets_roots
                resolved.native_roots = inner.native_roots
                resolved.package = inner.package or package
                return resolved
            resolved.split_skipped.append({
                "name": inner_entry,
                "reason": "nested container extraction "
                          "refused by the archive budget"})
    if base_entry is None and _depth >= MAX_CONTAINER_DEPTH:
        # No direct APK members and the depth limit forbids
        # following the nested container member: the limit
        # IS the refusal, and it must be named — the
        # pre-fix code returned the intermediate archive as
        # the base with no record of why resolution stopped
        # (certification D-02).
        nested = [{"name": n, "size_bytes": infos[n].file_size}
                  for n in names
                  if infos[n].filename.lower().endswith(
                      (".xapk", ".apkm", ".apks", ".zip"))
                  and not _traversal_name(infos[n].filename)]
        if nested:
            nested.sort(key=lambda c: c["name"])
            inner_entry = max(
                nested, key=lambda c: c["size_bytes"])["name"]
            resolved.split_skipped.append({
                "name": inner_entry,
                "reason": f"nested container depth limit "
                          f"({MAX_CONTAINER_DEPTH}) reached; "
                          "the nested container was not "
                          "resolved"})
    if base_entry is None:
        for c in contained:
            resolved.split_skipped.append({
                "name": c["name"],
                "reason": "no base APK identified in the "
                          "container"})
        resolved.obbs = _beside_obbs(path, package)
        return resolved

    # --- extract through safearchive ------------------------
    if work_dir:
        os.makedirs(work_dir, exist_ok=True)
        extract_root = work_dir
    else:
        extract_root = tempfile.mkdtemp(prefix="nar-container-")
        resolved._cleanup_dirs.append(extract_root)
    report = safe_extract(path, extract_root, budget)
    extracted = {e["entry"]: e["path"]
                 for e in report["extracted"]}
    rejected = {e["entry"]: e["reason"]
                for e in report["rejected"]}

    def _extracted_or_reason(entry):
        if entry in extracted:
            return extracted[entry], None
        return None, rejected.get(
            entry, "entry was not extracted")

    base_path, reason = _extracted_or_reason(base_entry)
    if base_path is None:
        resolved.split_skipped.append({
            "name": base_entry,
            "reason": f"base APK extraction refused: {reason}"})
        for c in contained:
            if c["name"] != base_entry:
                resolved.split_skipped.append({
                    "name": c["name"],
                    "reason": "base APK unavailable; split "
                              "not resolved"})
        resolved.obbs = _beside_obbs(path, package)
        return resolved
    resolved.base = base_path

    # Contained OBBs ride along as payload, extracted already.
    for n in names:
        if n.lower().endswith(".obb") and n in extracted:
            resolved.obbs.append({"path": extracted[n],
                                  "name": os.path.basename(n),
                                  "source": "container",
                                  "source_entry": n})
    resolved.obbs.extend(_beside_obbs(path, package))

    # --- splits ---------------------------------------------
    split_entries = [c["name"] for c in contained
                     if c["name"] != base_entry]
    # Manifest-declared splits that are absent on disk are
    # skipped with a named reason, never silently.
    declared = {s["file"] for s in
                (manifest or {}).get("split_apks") or []}
    # A declared split is present when either its raw stored
    # name or its normalised form is in the inventory (the
    # manifest spells names with '/', a stored name may
    # carry '\\').
    present = set(names) | {infos[n].filename for n in names}
    for missing in sorted(declared - present):
        resolved.split_skipped.append({
            "name": missing,
            "reason": "declared in container manifest but "
                      "absent from the container"})
    for entry in split_entries:
        s_kind = split_kind(entry)
        if not merge_splits:
            resolved.split_skipped.append({
                "name": entry,
                "reason": "split merge disabled "
                          "(--no-merge-splits)"})
            continue
        spath, sreason = _extracted_or_reason(entry)
        if spath is None:
            resolved.split_skipped.append({
                "name": entry,
                "reason": f"split extraction refused: "
                          f"{sreason}"})
            continue
        resolved.splits.append({
            "path": spath, "name": os.path.basename(entry),
            "kind": s_kind, "source_entry": entry})
        resolved.splits_merged.append({
            "name": os.path.basename(entry), "kind": s_kind,
            "source_entry": entry})

    resolved.assets_roots = [resolved.base] + \
        [s["path"] for s in resolved.splits]
    resolved.native_roots = list(resolved.assets_roots)

    # --- nested containers ----------------------------------
    # The base (or a split) may itself be a container
    # (ZIP -> XAPK -> APK): recurse and adopt the inner
    # resolution, keeping this level's records.
    if _depth < MAX_CONTAINER_DEPTH:
        inner_targets = [("base", resolved.base)] + \
            [("split", s["path"]) for s in resolved.splits]
        for role, candidate in inner_targets:
            if detect_container(candidate) not in \
                    CONTAINER_KINDS:
                continue
            inner = resolve_target(
                candidate, merge_splits=merge_splits,
                budget=budget, _depth=_depth + 1)
            resolved._cleanup_dirs.extend(inner._cleanup_dirs)
            inner._cleanup_dirs = []
            if role == "base" and inner.base != candidate:
                resolved.base = inner.base
            if role == "split" and inner.base != candidate:
                # A split that is itself a container: its
                # inner base takes the split's place.
                for s in resolved.splits:
                    if s["path"] == candidate:
                        s["path"] = inner.base
            for s in inner.splits:
                if s["path"] not in \
                        [x["path"] for x in resolved.splits]:
                    resolved.splits.append(s)
            resolved.splits_merged.extend(
                r for r in inner.splits_merged
                if r not in resolved.splits_merged)
            resolved.split_skipped.extend(inner.split_skipped)
            resolved.obbs.extend(
                o for o in inner.obbs
                if o["path"] not in
                [x["path"] for x in resolved.obbs])
            resolved.assets_roots = [resolved.base] + \
                [s["path"] for s in resolved.splits]
            resolved.native_roots = list(resolved.assets_roots)
    else:
        # Depth limit reached: a base (or split) that is
        # itself a container is left unopened — name the
        # refusal instead of silently presenting the
        # container file as the resolved target
        # (certification D-02).
        inner_targets = [("base", resolved.base,
                          resolved.base_entry)] + \
            [("split", s["path"],
              s.get("source_entry") or s["name"])
             for s in resolved.splits]
        for _role, candidate, entry_name in inner_targets:
            if detect_container(candidate) not in \
                    CONTAINER_KINDS:
                continue
            resolved.split_skipped.append({
                "name": entry_name
                or os.path.basename(candidate),
                "reason": f"nested container depth limit "
                          f"({MAX_CONTAINER_DEPTH}) reached; "
                          "the contained container was not "
                          "resolved"})
    return resolved


def resolution_block(path, budget=None):
    """A no-extraction resolution summary for reporters
    (nar-triage): the shared-rule base pick and split set,
    computed from the container inventory alone. Returns
    None for non-container inputs. An over-cap container
    manifest is refused under the same capped read as
    :func:`resolve_target` and named in ``split_skipped``."""
    kind = detect_container(path)
    if kind not in CONTAINER_KINDS:
        return None
    budget = ResourceBudget.from_safearchive_limits(budget)
    manifest_cap = min(budget.max_file_bytes,
                       MANIFEST_READ_CAP_BYTES)
    try:
        with zipfile.ZipFile(path) as zf:
            infos = {raw_entry_name(i): i
                     for i in zf.infolist()}
            manifest, manifest_refusal = \
                _manifest_and_refusal(zf, manifest_cap)
    except (zipfile.BadZipFile, OSError):
        return None
    contained = [{"name": n, "size_bytes": i.file_size}
                 for n, i in infos.items()
                 if i.filename.lower().endswith(".apk")
                 and not _traversal_name(i.filename)]
    contained.sort(key=lambda c: c["name"])
    stem = os.path.splitext(os.path.basename(path))[0]
    base = pick_base_apk(contained,
                         package=(manifest or {}).get("package"),
                         container_stem=stem)
    splits = [{"name": os.path.basename(c["name"]),
               "kind": split_kind(c["name"]),
               "source_entry": c["name"]}
              for c in contained if c["name"] != base]
    skipped = []
    if manifest_refusal:
        skipped.append({
            "name": "manifest.json",
            "reason": f"container manifest refused: "
                      f"{manifest_refusal}"})
    return {"input_kind": kind,
            "base": os.path.basename(base) if base else None,
            "base_entry": base,
            "splits_merged": splits,
            "split_skipped": skipped}


def inventory_duplicates(roots, cap_bytes=DUPLICATE_MEMBER_CAP_BYTES,
                         predicate=None):
    """Duplicate/delta detection across a set of archives.

    Hashes member content (bounded: a member over
    ``cap_bytes`` is skipped-and-noted, never materialized
    whole) and reports each content hash that occurs in
    more than one location ONCE, with all its locations.
    ``predicate`` optionally filters member names.
    Returns {"duplicate_groups": [{sha256, size_bytes,
    locations: [{archive, member}]}], "skipped_oversized":
    [{archive, member, size_bytes, reason}],
    "members_hashed": int}."""
    by_hash = {}
    skipped = []
    hashed = 0
    for root in roots:
        archive = os.path.basename(root)
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for info in zf.infolist():
                # Decisions (directory, predicate) use the
                # normalised name; every cited member name
                # (skipped records, duplicate locations) is
                # the raw stored name.
                name = info.filename
                raw = raw_entry_name(info)
                if name.endswith("/"):
                    continue
                if predicate is not None and not predicate(name):
                    continue
                if info.file_size > cap_bytes:
                    skipped.append({
                        "archive": archive, "member": raw,
                        "size_bytes": info.file_size,
                        "reason": f"member exceeds the "
                                  f"{cap_bytes}-byte duplicate-"
                                  f"inventory hash cap"})
                    continue
                digest = hashlib.sha256()
                try:
                    with zf.open(name) as fh:
                        while True:
                            chunk = fh.read(1 << 20)
                            if not chunk:
                                break
                            digest.update(chunk)
                except (KeyError, OSError, RuntimeError,
                        zipfile.BadZipFile):
                    continue
                hashed += 1
                slot = by_hash.setdefault(
                    digest.hexdigest(),
                    {"sha256": digest.hexdigest(),
                     "size_bytes": info.file_size,
                     "locations": []})
                slot["locations"].append(
                    {"archive": archive, "member": raw})
    groups = [g for g in by_hash.values()
              if len(g["locations"]) > 1]
    for g in groups:
        g["locations"].sort(
            key=lambda loc: (loc["archive"], loc["member"]))
    groups.sort(key=lambda g: g["sha256"])
    return {"duplicate_groups": groups,
            "skipped_oversized": skipped,
            "members_hashed": hashed}
