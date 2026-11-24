"""Read-only file mapping for the narlib parsers.

The parsers (iostore, zen, uasset, elf, and nar-pak's index
reader) work by slicing and struct.unpack_from, which an
mmap supports exactly like bytes — except that every slice
of an mmap copies only the bytes actually touched, while
reading a whole file into bytes materializes all of it.
Callers that parse a large on-disk file (a .ucas, an .so, a
.pak) map it with mapped_file() instead of fh.read(); the
parsers keep accepting plain bytes unchanged (zip members
and test fixtures still pass bytes).

mapped_file(path) is a context manager: it yields an
mmap.mmap (ACCESS_READ) for a regular file, or the file's
bytes for a tiny file (below _TINY_BYTES, where a copy is
cheaper than a mapping) or when mmap is unavailable /
fails for the file. The mapping (and the underlying file
handle) is closed when the context exits, whichever way it
was opened; the yielded object must not be used after the
context exits.
"""
import contextlib
import mmap
import os

# Files at or below this size are read as bytes: the copy
# is a few pages at most and avoids mmap setup entirely.
_TINY_BYTES = 64 * 1024


@contextlib.contextmanager
def mapped_file(path):
    """Yield a read-only mmap of path (or bytes fallback).

    Raises the same OSError open()/os.path.getsize() raise
    for a missing or unreadable file."""
    size = os.path.getsize(path)
    if size <= _TINY_BYTES:
        with open(path, "rb") as fh:
            yield fh.read()
        return
    fh = open(path, "rb")
    try:
        try:
            mapping = mmap.mmap(fh.fileno(), 0,
                                access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            fh.seek(0)
            yield fh.read()
            return
        try:
            yield mapping
        finally:
            mapping.close()
    finally:
        fh.close()
