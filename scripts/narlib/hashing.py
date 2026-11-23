"""Streaming hashes (SHA-256) shared by the 2.0 modules."""
import hashlib

_CHUNK = 1 << 20


def sha256_of(path):
    """SHA-256 of a file, read in chunks (never whole-file)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_bytes(data):
    return hashlib.sha256(data).hexdigest()
