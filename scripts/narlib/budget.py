"""Resource budgets for untrusted-input handling.

One named abstraction for the ceilings that were previously
scattered as ad-hoc constants across the archive and member-read
paths (2.6.2 Workstream A). A :class:`ResourceBudget` states, in
one place, how much work a single untrusted input may cause:

- ``max_entries`` -- archive member count,
- ``max_file_bytes`` -- per-member decompressed size,
- ``max_total_bytes`` -- whole-archive decompressed size,
- ``max_compression_ratio`` -- per-entry ratio (bomb guard),
- ``max_total_ratio`` -- whole-archive ratio,
- ``max_nesting_depth`` -- archives inside archives,
- ``max_elapsed_seconds`` -- wall-clock budget, or ``None``
  for no time budget (the historical default).

Defaults are aligned with ``narlib.safearchive.DEFAULT_LIMITS``
so a default budget and the historical safearchive limits are
the same policy stated twice, not two policies.

Overrides are validated: negative, zero (where a positive value
is required), non-numeric, or absurd values raise
:class:`BudgetError` -- a named error, never a bare
``ValueError``/``TypeError`` leak from deep inside an extractor
and never a silent clamp. "Absurd" bounds are deliberately
generous (far above any real input NAR handles); they exist to
catch unit mistakes such as bytes-vs-gigabytes slips, not to
tighten policy.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
"""
import math
from dataclasses import dataclass, field

# Absurd-value ceilings for override validation.
_MAX_ENTRIES_CEILING = 10_000_000
_MAX_BYTES_CEILING = 64 * 1024 * 1024 * 1024  # 64 GiB
_MAX_RATIO_CEILING = 100_000.0
_MAX_NESTING_CEILING = 32
_MAX_ELAPSED_CEILING = 86_400.0  # 24 h


class BudgetError(Exception):
    """A ResourceBudget override is invalid or absurd."""


def _check_int(name, value, ceiling, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int):
        raise BudgetError(
            f"ResourceBudget.{name} must be an int, "
            f"got {type(value).__name__}")
    if value < minimum:
        raise BudgetError(
            f"ResourceBudget.{name} must be >= {minimum}, "
            f"got {value}")
    if value > ceiling:
        raise BudgetError(
            f"ResourceBudget.{name}={value} exceeds the "
            f"absurd-value ceiling {ceiling}")
    return value


def _check_ratio(name, value):
    if isinstance(value, bool) or not isinstance(
            value, (int, float)):
        raise BudgetError(
            f"ResourceBudget.{name} must be a number, "
            f"got {type(value).__name__}")
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise BudgetError(
            f"ResourceBudget.{name} must be a positive "
            f"finite number, got {value}")
    if value > _MAX_RATIO_CEILING:
        raise BudgetError(
            f"ResourceBudget.{name}={value} exceeds the "
            f"absurd-value ceiling {_MAX_RATIO_CEILING}")
    return value


@dataclass(frozen=True)
class ResourceBudget:
    """Validated resource ceilings for one untrusted input."""

    max_entries: int = 20_000
    max_file_bytes: int = 1024 * 1024 * 1024
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_total_ratio: float = 100.0
    max_nesting_depth: int = 2
    max_elapsed_seconds: float = None

    def __post_init__(self):
        object.__setattr__(self, "max_entries", _check_int(
            "max_entries", self.max_entries,
            _MAX_ENTRIES_CEILING, minimum=1))
        object.__setattr__(self, "max_file_bytes", _check_int(
            "max_file_bytes", self.max_file_bytes,
            _MAX_BYTES_CEILING, minimum=1))
        object.__setattr__(self, "max_total_bytes", _check_int(
            "max_total_bytes", self.max_total_bytes,
            _MAX_BYTES_CEILING, minimum=1))
        object.__setattr__(self, "max_compression_ratio",
                           _check_ratio("max_compression_ratio",
                                        self.max_compression_ratio))
        object.__setattr__(self, "max_total_ratio",
                           _check_ratio("max_total_ratio",
                                        self.max_total_ratio))
        object.__setattr__(self, "max_nesting_depth", _check_int(
            "max_nesting_depth", self.max_nesting_depth,
            _MAX_NESTING_CEILING, minimum=0))
        if self.max_elapsed_seconds is not None:
            elapsed = self.max_elapsed_seconds
            if isinstance(elapsed, bool) or not isinstance(
                    elapsed, (int, float)):
                raise BudgetError(
                    "ResourceBudget.max_elapsed_seconds must "
                    f"be a number or None, got "
                    f"{type(elapsed).__name__}")
            elapsed = float(elapsed)
            if not math.isfinite(elapsed) or elapsed <= 0:
                raise BudgetError(
                    "ResourceBudget.max_elapsed_seconds must "
                    f"be positive and finite, got {elapsed}")
            if elapsed > _MAX_ELAPSED_CEILING:
                raise BudgetError(
                    "ResourceBudget.max_elapsed_seconds="
                    f"{elapsed} exceeds the absurd-value "
                    f"ceiling {_MAX_ELAPSED_CEILING}")
            object.__setattr__(self, "max_elapsed_seconds",
                               elapsed)

    # -- mappings ------------------------------------------------
    def to_safearchive_limits(self):
        """The ``narlib.safearchive`` limits-dict shape."""
        return {
            "max_entries": self.max_entries,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_ratio": self.max_compression_ratio,
            "max_total_ratio": self.max_total_ratio,
            "max_nesting": self.max_nesting_depth,
        }

    @classmethod
    def from_safearchive_limits(cls, limits):
        """Build a budget from a (partial) safearchive limits
        dict. Unknown keys are ignored, matching the historical
        safearchive merge semantics (extra keys were carried in
        the merged dict and never consulted); known values are
        validated and invalid ones raise BudgetError."""
        if limits is None:
            return cls()
        if isinstance(limits, ResourceBudget):
            return limits
        if not isinstance(limits, dict):
            raise BudgetError(
                "limits must be a dict or ResourceBudget, "
                f"got {type(limits).__name__}")
        kwargs = {}
        if "max_entries" in limits:
            kwargs["max_entries"] = limits["max_entries"]
        if "max_total_bytes" in limits:
            kwargs["max_total_bytes"] = limits["max_total_bytes"]
        if "max_file_bytes" in limits:
            kwargs["max_file_bytes"] = limits["max_file_bytes"]
        if "max_ratio" in limits:
            kwargs["max_compression_ratio"] = limits["max_ratio"]
        if "max_total_ratio" in limits:
            kwargs["max_total_ratio"] = limits["max_total_ratio"]
        if "max_nesting" in limits:
            kwargs["max_nesting_depth"] = limits["max_nesting"]
        if "max_elapsed_seconds" in limits:
            kwargs["max_elapsed_seconds"] = \
                limits["max_elapsed_seconds"]
        return cls(**kwargs)


#: The default policy: identical values to
#: ``narlib.safearchive.DEFAULT_LIMITS``.
DEFAULT_BUDGET = ResourceBudget()
