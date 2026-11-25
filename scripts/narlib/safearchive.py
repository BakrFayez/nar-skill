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
import time
import zipfile

from .budget import ResourceBudget

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


def raw_entry_name(info):
    """The entry name exactly as stored in the archive.

    CPython's zipfile normalises ``ZipInfo.filename`` on
    Windows (os.sep and os.altsep become '/') both when
    writing and when reading the central directory, while
    ``ZipInfo.orig_filename`` preserves the stored name.
    Reports are evidence: they must cite the name as it
    appears in the archive, so every report key in this
    module (and in consumers keying maps by entry name)
    uses this raw name. The containment/traversal
    DECISIONS keep using the normalised ``info.filename``
    exactly as before -- normalisation is for the decision,
    never for the citation. On platforms where no
    normalisation happens the two are identical."""
    return getattr(info, "orig_filename", None) or info.filename


def _entry_problems(info, limits, totals):
    """Return a rejection reason for a ZipInfo, or None."""
    name = info.filename
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        # Checked before the directory early return: a
        # symlink entry wearing a trailing slash used to
        # be skipped silently, against this module's
        # "nothing is silently skipped" rule (stability
        # audit C-14).
        return "symlink entry"
    if name.endswith("/"):
        return None  # directory entry: nothing to write
    if name.startswith("/") or name.startswith("\\"):
        return "absolute path"
    if len(name) > 1 and name[1] == ":":
        return "drive-letter path"
    parts = name.replace("\\", "/").split("/")
    if ".." in parts:
        return "path traversal (..)"
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


#: Default ceiling for read_member_capped (the nar-rn
#: snapshot precedent): no single archive member a NAR
#: tool materializes in memory may exceed this.
MEMBER_READ_CAP_BYTES = 256 * 1024 * 1024


def read_member_capped(zf, name, cap_bytes=MEMBER_READ_CAP_BYTES):
    """Read one zip member fully, under a hard cap.

    The declared size is checked BEFORE decompression
    and the streamed byte count is checked again while
    reading (a crafted central directory can understate
    the size). Raises ValueError over the cap. Several
    tools previously materialized members with a bare
    zf.read() — a small hostile APK with a huge inflated
    member drove hundreds of MB of peak RSS through the
    analysis pipeline (stability audit D-05)."""
    info = zf.getinfo(name)
    if info.file_size > cap_bytes:
        raise ValueError(
            f"archive member {name!r} declares "
            f"{info.file_size} bytes, over the "
            f"{cap_bytes}-byte member read cap")
    out = bytearray()
    with zf.open(name) as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            out += chunk
            if len(out) > cap_bytes:
                raise ValueError(
                    f"archive member {name!r} exceeded "
                    f"the {cap_bytes}-byte member read "
                    "cap while streaming (declared size "
                    "understated)")
    return bytes(out)


def _is_archive_name(name):
    return name.lower().endswith(_ARCHIVE_EXTS)


def safe_extract(zip_path, dest_dir, limits=None, _depth=0):
    """Extract a zip-family file under the guard limits.

    ``limits`` is a partial limits dict (the historical shape)
    or a ``narlib.budget.ResourceBudget``; both are normalized
    to a ResourceBudget internally (2.6.2) and validated --
    invalid values raise ``narlib.budget.BudgetError``.

    Returns {extracted: [{entry, path, size_bytes}], rejected:
    [{entry, reason}], nested_archives: [names], totals}.
    Every ``entry``/nested name cites the RAW name as stored
    in the archive (see :func:`raw_entry_name`); ``path`` is
    the real contained on-disk path.
    Nested archives are listed, and extracted as plain files;
    recursion into them happens only when the caller drives it
    (depth is tracked and reported, never automatic).

    Duplicate member names: both entries are processed in
    central-directory order; the second write lands on the same
    contained target and replaces the first file's contents.
    That is deterministic, stays inside the destination, and
    both entries appear in ``extracted`` -- it is never a
    silent escape, but callers that care about first-wins
    semantics must dedupe themselves.
    """
    budget = ResourceBudget.from_safearchive_limits(limits)
    limits = {**DEFAULT_LIMITS, **budget.to_safearchive_limits()}
    started = time.monotonic()
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
            # ``name`` is the normalised name: every decision
            # (traversal, containment, on-disk path) uses it,
            # unchanged. ``raw`` is the name as stored in the
            # archive: every report citation uses it.
            name = info.filename
            raw = raw_entry_name(info)
            if name.endswith("/"):
                # Directory entries write nothing, but a
                # symlink-mode directory entry is a
                # rejection, not a skip (C-14).
                reason = _entry_problems(info, limits, totals)
                if reason:
                    report["rejected"].append(
                        {"entry": raw, "reason": reason})
                continue
            if budget.max_elapsed_seconds is not None and \
                    time.monotonic() - started > \
                    budget.max_elapsed_seconds:
                report["rejected"].append({
                    "entry": raw,
                    "reason": "elapsed time budget exceeded "
                              f"({budget.max_elapsed_seconds}s)"})
                continue
            reason = _entry_problems(info, limits, totals)
            if reason:
                report["rejected"].append({"entry": raw,
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
                    {"entry": raw, "reason": "escapes destination"})
                continue
            if os.path.islink(target):
                # A pre-existing symlink FILE at the target
                # path whose target lies inside the
                # destination passes the containment proof,
                # but open("wb") would follow it and
                # overwrite a different file (stability
                # audit C-15). Refuse to write through any
                # link at the final component.
                report["rejected"].append(
                    {"entry": raw,
                     "reason": "target path is a pre-existing "
                               "symlink"})
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
                    {"entry": raw, "reason": overflow})
                continue
            totals["bytes"] += written
            report["extracted"].append(
                {"entry": raw, "path": target,
                 "size_bytes": written})
            if _is_archive_name(name):
                report["nested_archives"].append(raw)
        report["totals"]["bytes"] = totals["bytes"]
    if report["nested_archives"] and _depth >= limits["max_nesting"]:
        report["nesting_limit_reached"] = True
    return report
