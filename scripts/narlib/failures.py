"""narlib.failures: the single failure-classification enum
(Part 10.5).

Every failure a fallback chain records is classified with
exactly one FailureKind. Free-form failure strings are
forbidden in chain records: an attempt's ``reason`` is
always ``"<KIND>: <detail>"`` where ``<KIND>`` is a
FailureKind name, and the same name rides in the attempt's
``classification`` field, so aggregators (a later
``nar coverage --gap``) group by classification without
parsing prose.

The classifiers here are pure stdlib string/exception
inspection of outcomes the adapters already return — they
never run a tool themselves.

Part of NAR (Nirous Android Reversing). MIT License.
See LICENSE in the repo root.
"""
import enum
import traceback


class FailureKind(str, enum.Enum):
    """The closed set of failure classifications."""

    NOT_INSTALLED = "NOT_INSTALLED"
    INSTALLED_WONT_START = "INSTALLED_WONT_START"
    WRONG_VERSION = "WRONG_VERSION"
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
    PROTECTED_INPUT = "PROTECTED_INPUT"
    CORRUPT_INPUT = "CORRUPT_INPUT"
    TIMEOUT = "TIMEOUT"
    OOM = "OOM"
    PARTIAL = "PARTIAL"
    BUG = "BUG"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


FAILURE_KIND_NAMES = frozenset(k.value for k in FailureKind)

# Bounded self-repair / report labels (brief 10.5.5). OOM and
# TIMEOUT name the one-shot repair the chain runner may
# attempt; the rest name what the report must say instead of
# a repair. Kinds absent here have no repair and no label.
_REPAIR_LABELS = {
    FailureKind.OOM: "oom-retry",
    FailureKind.TIMEOUT: "timeout-retry",
}
_REPORT_LABELS = {
    FailureKind.OOM: "oom-retry",
    FailureKind.TIMEOUT: "timeout-retry",
    FailureKind.INSTALLED_WONT_START: "needs-jdk",
    FailureKind.NOT_INSTALLED: "needs-install",
    FailureKind.CORRUPT_INPUT: "input-defect",
    FailureKind.BUG: "internal-bug",
}

_OOM_MARKERS = (
    "outofmemoryerror", "out of memory", "java heap space",
    "gc overhead limit", "cannot allocate memory",
    "memoryerror",
)
_WONT_START_MARKERS = (
    "java_home is not set", "java_home is not defined",
    "java_home is set to an invalid directory",
    "jdk not found", "java not found",
    "could not find or load main class",
    "unsupportedclassversionerror",
    "could not create the java virtual machine",
    "error occurred during initialization of vm",
    "cannot execute binary file", "exec format error",
)
_WRONG_VERSION_MARKERS = (
    "wrong version", "version too old", "version is below",
    "below the required", "requires a newer", "too old",
)
_PROTECTED_MARKERS = (
    "protected dex", "encrypted dex", "packed dex",
    "dex is protected", "input is protected",
)
_CORRUPT_MARKERS = (
    "bad magic", "invalid dex", "dexexception",
    "checksum", "corrupt", "truncated",
    "unexpected end of file", "not a dex file",
    "invalid header", "invalid zip", "bad zip",
)
_UNSUPPORTED_MARKERS = (
    "unsupported input", "unsupported format",
    "unsupported version", "unknown format",
    "not supported", "unsupported dex version",
)


def kind_name(kind):
    """The enum name for a FailureKind (or a validated str)."""
    if isinstance(kind, FailureKind):
        return kind.value
    text = str(kind)
    if text not in FAILURE_KIND_NAMES:
        raise ValueError(f"not a FailureKind name: {text!r}")
    return text


def coerce_kind(value, default=FailureKind.BUG):
    """Coerce a producer-supplied classification to a
    FailureKind. Anything that is not exactly one enum name
    becomes ``default`` — a chain record never carries a
    free-form classification."""
    if isinstance(value, FailureKind):
        return value
    if isinstance(value, str) and value in FAILURE_KIND_NAMES:
        return FailureKind(value)
    return default


def format_reason(kind, detail=""):
    """``"<KIND>: <detail>"`` — the only reason shape a
    failed/partial chain attempt may carry."""
    name = kind_name(kind)
    detail = str(detail or "").strip()
    return f"{name}: {detail}" if detail else name


def repair_label_for(kind):
    """The one-shot repair label for a kind, or None."""
    kind = coerce_kind(kind, None)
    return _REPAIR_LABELS.get(kind) if kind is not None else None


def report_label_for(kind):
    """The brief 10.5.5 report label for a kind, or None."""
    kind = coerce_kind(kind, None)
    return _REPORT_LABELS.get(kind) if kind is not None else None


def _contains(text, markers):
    return any(m in text for m in markers)


def classify_output(output, returncode=None):
    """Classify a finished subprocess outcome from its
    combined output text (and exit code when known).

    Order matters: an OOM banner is an OOM even when the
    launcher also complains; a JDK/start banner is
    INSTALLED_WONT_START (the tool is present but cannot
    start) before any generic version reading.
    """
    text = (output or "").lower()
    if _contains(text, _OOM_MARKERS):
        return FailureKind.OOM
    if returncode in (137, -9) and not text:
        return FailureKind.OOM
    if _contains(text, _WONT_START_MARKERS):
        return FailureKind.INSTALLED_WONT_START
    if _contains(text, _WRONG_VERSION_MARKERS):
        return FailureKind.WRONG_VERSION
    if _contains(text, _PROTECTED_MARKERS):
        return FailureKind.PROTECTED_INPUT
    if _contains(text, _CORRUPT_MARKERS):
        return FailureKind.CORRUPT_INPUT
    if _contains(text, _UNSUPPORTED_MARKERS):
        return FailureKind.UNSUPPORTED_INPUT
    if "timed out" in text or "timeout expired" in text:
        return FailureKind.TIMEOUT
    return FailureKind.BUG


def classify_subprocess(returncode=None, output="",
                        timed_out=False, exception=None):
    """Classify a subprocess outcome: missing binary,
    start failure, timeout, OOM, or (fallback) BUG."""
    if timed_out:
        return FailureKind.TIMEOUT
    if exception is not None:
        return classify_exception(exception)
    return classify_output(output, returncode=returncode)


def classify_exception(exc):
    """Classify an exception raised in our own process.

    A missing executable is NOT_INSTALLED; a timeout is
    TIMEOUT; a memory failure is OOM; anything else is a
    BUG in our own code (the caller logs the traceback).
    """
    name = type(exc).__name__
    if name in ("FileNotFoundError", "NotADirectoryError"):
        return FailureKind.NOT_INSTALLED
    if name == "TimeoutExpired" or "timed out" in str(exc).lower():
        return FailureKind.TIMEOUT
    if name == "MemoryError":
        return FailureKind.OOM
    return FailureKind.BUG


def classify_unavailable(note):
    """Classify a registry probe's not-available note."""
    text = (note or "").lower()
    if "tool_identity_mismatch" in text:
        # A tool is present at the expected name/path but
        # provably is not the tool it claims to be (field
        # round F-04): the wrong tool, classified like the
        # wrong version — never as a bare absence.
        return FailureKind.WRONG_VERSION
    if "below the required" in text or "wrong version" in text:
        return FailureKind.WRONG_VERSION
    if "did not run" in text or "did not start" in text:
        return FailureKind.INSTALLED_WONT_START
    # "not found", "not importable", "not integrated in
    # this release": the tool is not there to run.
    return FailureKind.NOT_INSTALLED


def classify_adapter_error(error, output_tail=""):
    """Classify the ``{"error": ...}`` shapes the existing
    nar-dex adapters (run_adapter / jadx_index /
    baksmali_index) return, without changing those shapes.

    Returns (FailureKind, detail) where detail is the
    adapter's own text, kept after the enum prefix.
    """
    text = str(error or "")
    low = text.lower()
    tail_kind = None
    if output_tail:
        tail_kind = classify_output(output_tail)
    if "not in registry" in low:
        return FailureKind.BUG, text
    if "not available:" in low:
        note = text.split("not available:", 1)[1].strip()
        return classify_unavailable(note), text
    if "timed out" in low or "timeout" in low and "failed" in low:
        return FailureKind.TIMEOUT, text
    if tail_kind is not None and tail_kind is not FailureKind.BUG:
        return tail_kind, text
    if "run failed" in low:
        inner = classify_output(text)
        if inner is not FailureKind.BUG:
            return inner, text
        if tail_kind is not None:
            return tail_kind, text
        return FailureKind.BUG, text
    return coerce_kind(classify_output(text)), text


def traceback_text(exc):
    """The traceback string a BUG attempt records."""
    return "".join(traceback.format_exception(
        type(exc), exc, exc.__traceback__))[-2000:]
