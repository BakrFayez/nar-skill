"""narlib: shared core library for the NAR 2.0 modules.

The 1.x scripts stay standalone by design (they are the
compatibility surface). New 2.0 modules import from here
instead of growing another copy of each helper.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""

__version__ = "3.0.1"

FACT_CLASSES = ("observed", "derived", "inferred", "hypothesis",
                "unknown")
CONFIDENCE_LEVELS = ("high", "medium", "low")
RESULT_STATUSES = ("ok", "partial", "degraded", "failed",
                   "skipped", "unsupported")
# Verification status (brief section 13; Evolution Phases
# 6/8): how strongly a result is verified, independent of
# how confident the analysis is. CONFIRMED = read directly
# from the target or reproduced by an independent check;
# STRONGLY_INDICATED = multiple indicators agree but the
# claim rests on interpretation; POTENTIAL = a single weak
# indicator or a review prompt; UNVERIFIED = asserted by a
# tool/stage but not checked; CONTRADICTED = another check
# disagrees (the disagreement is reported, never hidden).
VERIFICATION_STATUSES = ("CONFIRMED", "STRONGLY_INDICATED",
                         "POTENTIAL", "UNVERIFIED",
                         "CONTRADICTED")
