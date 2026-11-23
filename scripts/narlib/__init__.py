"""narlib: shared core library for the NAR 2.0 modules.

The 1.x scripts stay standalone by design (they are the
compatibility surface). New 2.0 modules import from here
instead of growing another copy of each helper.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""

__version__ = "2.3.0"

FACT_CLASSES = ("observed", "derived", "inferred", "hypothesis",
                "unknown")
CONFIDENCE_LEVELS = ("high", "medium", "low")
RESULT_STATUSES = ("ok", "partial", "degraded", "failed",
                   "skipped", "unsupported")
