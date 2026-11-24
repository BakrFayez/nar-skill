"""Safe archive extraction.

Every archive NAR touches is untrusted input (brief rules 21,
25). This layer is the only sanctioned way for 2.0 modules to
extract: it refuses, and REPORTS, entries that are

- absolute paths or path-traversal attempts (``..``, drive
  letters, backslash traversal),
- symlinks or other non-regular entries,
- beyond the entry-count, total-size, per-file-size, or
  compression-ratio (archive bomb) limits,
- nested archives deeper than the configured depth when
  recursion is enabled.

Nothing is silently skipped: the report lists every rejection
with its reason. Extraction writes regular files only, under
the destination directory, with sanitized relative paths.
"""
import os
import stat
import zipfile

DEFAULT_LIMITS = {
    "max_entries": 20000,
    "max_total_bytes": 2 * 1024 * 1024 * 1024,
    "max_file_bytes": 1024 * 1024 * 1024,
    "max_ratio": 200.0,          # per-entry uncompressed/compressed
    "max_total_ratio": 100.0,    # whole-archive ratio
    "max_nesting": 2,            # archives inside archives
}

_ARCHIVE_EXTS = (".zip", ".apk", ".aab", ".xapk", ".apkm", ".apks",
                 ".aar", ".jar", ".obb")


def _entry_problems(info, limits, totals):
    """Return a rejection reason for a ZipInfo, or None."""
    name = info.filename
    if name.endswith("/"):
        return None  # directory entry: nothing to write
    if name.startswith("/") or name.startswith("\\"):
        return "absolute path"
    if len(name) > 1 and name[1] == ":":
        return "drive-letter path"
    parts = name.replace("\\", "/").split("/")
    if ".." in parts:
        return "path traversal (..)"
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        return "symlink entry"
    # File-type bits are authoritative only when present; many
    # writers store bare permission bits (no type), which means
    # a regular file.
    if mode & 0o170000 and not (stat.S_ISREG(mode)
                                or stat.S_ISDIR(mode)):
        return "non-regular entry"
    if info.file_size > limits["max_file_bytes"]:
        return "file exceeds per-file size limit"
    if info.compress_size > 0:
        ratio = info.file_size / info.compress_size
        if ratio > limits["max_ratio"]:
            return f"compression ratio {ratio:.0f} exceeds limit"
    if totals["bytes"] + info.file_size > limits["max_total_bytes"]:
        return "archive exceeds total size limit"
    return None


def _is_archive_name(name):
    return name.lower().endswith(_ARCHIVE_EXTS)


def safe_extract(zip_path, dest_dir, limits=None, _depth=0):
    """Extract a zip-family file under the guard limits.

    Returns {extracted: [{entry, path, size_bytes}], rejected:
    [{entry, reason}], nested_archives: [names], totals}.
    Nested archives are listed, and extracted as plain files;
    recursion into them happens only when the caller drives it
    (depth is tracked and reported, never automatic).
    """
    limits = {**DEFAULT_LIMITS, **(limits or {})}
    report = {"source": zip_path, "dest": dest_dir, "depth": _depth,
              "extracted": [], "rejected": [], "nested_archives": [],
              "totals": {"entries": 0, "bytes": 0}}
    os.makedirs(dest_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        report["totals"]["entries"] = len(infos)
        if len(infos) > limits["max_entries"]:
            report["rejected"].append({
                "entry": "(whole archive)",
                "reason": f"entry count {len(infos)} exceeds limit "
                          f"{limits['max_entries']}"})
            return report
        total_comp = sum(i.compress_size for i in infos)
        total_raw = sum(i.file_size for i in infos)
        if total_comp > 0 and total_raw / total_comp > limits["max_total_ratio"]:
            report["rejected"].append({
                "entry": "(whole archive)",
                "reason": f"total compression ratio "
                          f"{total_raw / total_comp:.0f} exceeds limit"})
            return report
        totals = {"bytes": 0}
        for info in infos:
            name = info.filename
            if name.endswith("/"):
                continue
            reason = _entry_problems(info, limits, totals)
            if reason:
                report["rejected"].append({"entry": name,
                                           "reason": reason})
                continue
            rel = name.replace("\\", "/")
            target = os.path.join(dest_dir, rel)
            # Final containment proof, independent of the checks
            # above: the resolved target must stay inside dest.
            dest_real = os.path.realpath(dest_dir)
            target_real = os.path.realpath(target)
            if not (target_real == dest_real or
                    target_real.startswith(dest_real + os.sep)):
                report["rejected"].append(
                    {"entry": name, "reason": "escapes destination"})
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            # Limits are enforced on ACTUAL bytes written,
            # never on the header-declared sizes alone: a
            # crafted entry whose decompressed stream runs
            # past its declared file_size (or past the
            # per-file / total limits) is cut off, the
            # partial file is removed, and the entry is
            # reported rejected (Phase 10 audit).
            written = 0
            overflow = None
            try:
                with zf.open(info) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > limits["max_file_bytes"]:
                            overflow = ("actual decompressed size "
                                        "exceeds per-file size "
                                        "limit")
                            break
                        if (totals["bytes"] + written
                                > limits["max_total_bytes"]):
                            overflow = ("actual decompressed size "
                                        "exceeds total size limit")
                            break
                        dst.write(chunk)
            except (zipfile.BadZipFile, RuntimeError, EOFError,
                    OSError) as e:
                # A corrupt or header-lying entry (bad CRC,
                # truncated stream, encrypted without a key)
                # rejects that entry alone; it must not abort
                # the whole extraction (Phase 10 audit).
                overflow = f"entry unreadable: {e}"
            if overflow:
                try:
                    os.unlink(target)
                except OSError:
                    pass
                report["rejected"].append(
                    {"entry": name, "reason": overflow})
                continue
            totals["bytes"] += written
            report["extracted"].append(
                {"entry": name, "path": target,
                 "size_bytes": written})
            if _is_archive_name(name):
                report["nested_archives"].append(name)
        report["totals"]["bytes"] = totals["bytes"]
    if report["nested_archives"] and _depth >= limits["max_nesting"]:
        report["nesting_limit_reached"] = True
    return report
