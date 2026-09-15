"""Week 3 task (W3.3): response-class mapping. Converts the three dimension
scores (docs/scoring_rubric_v0.1.md) into a recommended defensive response --
the object of the response-routing evaluation (PR1 Evaluation #6): the
fraction of records where this mapping recommends something other than
"patch," compared against what severity ranking alone would imply.

Four classes, named in PR1's Methodology Paragraph Summary:

  - FIX_OBTAINABLE        : patch. The chain holds end to end.
  - FIX_STATED_NOT_OBTAINABLE : the record says a fix exists, but the
    defender cannot retrieve it (dead advisory, gated firmware). Response:
    escalate to the vendor / try archive sources, not "patch as normal."
  - NO_FIX_STATED_SUPPORTED   : no fix is identified, but nothing indicates
    the model is out of support either. Response: mitigate (segment,
    disable remote admin) while watching for a fix, not "low priority."
  - NO_FIX_EOL                : no fix, and the model is out of support.
    Response: replace or permanently mitigate -- no amount of waiting
    produces a patch. This is the end-of-life stakeholder class from PR1's
    stakeholder table.

`classify_response()` takes the identifiability score (informational only --
it does not gate the response class, since a defender who already knows
their device is affected does not need identifiability to also be perfect
before acting on fix availability/obtainability), the fix-availability
score, and the fix-obtainability score (nullable -- Dimension 3 is not
implemented until Week 6; see below).

End-of-life detection: PR1 Appendix / stakeholder analysis already flags
this as the hardest input ("the difficulty of machine-determining
end-of-support status" -- PR1 Limitations, and D8/AD-3). This module does
NOT attempt to determine EOL status automatically. `eol` is a required,
explicit argument; when the caller has no automated EOL signal (the
common case at design-lock time), pass `eol=None` and the mapping falls
back to NO_FIX_STATED_SUPPORTED_OR_EOL_UNKNOWN, keeping the "no fix,
EOL-unknown" case visibly distinct from a record where the model is
confirmed supported. Collapsing it into "supported" would overstate the
metric's confidence; collapsing it into "EOL" would understate it.
"""
from __future__ import annotations

from enum import Enum


class ResponseClass(Enum):
    FIX_OBTAINABLE = "fix identified and obtainable -- patch"
    FIX_STATED_NOT_OBTAINABLE = "fix stated but not obtainable -- escalate/archive, not routine patch"
    NO_FIX_STATED_SUPPORTED = "no fix stated, model confirmed supported -- mitigate, watch for fix"
    NO_FIX_EOL = "no fix, model end-of-life -- mitigate or replace, no fix is coming"
    NO_FIX_EOL_UNKNOWN = "no fix stated, support status unknown -- mitigate pending manual EOL check"


def classify_response(
    fix_availability_score: int,
    fix_obtainability_score: int | None,
    eol: bool | None,
) -> ResponseClass:
    """fix_obtainability_score: None means Dimension 3 has not been scored
    for this record yet (pre-Week-6). In that case a fix_availability_score
    of 2 is treated as provisionally obtainable-pending-verification and
    still routed to FIX_OBTAINABLE, since D4/D5 defines obtainability as a
    live-reachability check layered on top of an already-identified fix --
    reporting on this provisional routing before Dimension 3 lands must
    note that provisionality explicitly (see docs/response_class_mapping.md)."""
    fix_identified = fix_availability_score >= 2

    if fix_identified:
        if fix_obtainability_score is None:
            return ResponseClass.FIX_OBTAINABLE  # provisional -- see docstring
        if fix_obtainability_score >= 1:
            return ResponseClass.FIX_OBTAINABLE
        return ResponseClass.FIX_STATED_NOT_OBTAINABLE

    # No fix clearly identified (fix_availability_score 0 or 1).
    if eol is True:
        return ResponseClass.NO_FIX_EOL
    if eol is False:
        return ResponseClass.NO_FIX_STATED_SUPPORTED
    return ResponseClass.NO_FIX_EOL_UNKNOWN


def implies_non_patch_response(response: ResponseClass) -> bool:
    """True for every class except the routine-patch case -- this is exactly
    the response-routing evaluation's numerator (PR1 Evaluation #6)."""
    return response is not ResponseClass.FIX_OBTAINABLE
