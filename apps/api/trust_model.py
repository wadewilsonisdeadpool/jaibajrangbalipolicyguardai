"""Behavioral trust v3: Bayesian reputation with evidence decay.

Why this is more realistic than a single number nudged up and down:

1. Trust is a Beta(alpha, beta) belief. Good outcomes add positive
   evidence, bad outcomes add negative evidence. Trust = expected value.
2. Confidence matters. A newcomer with no history is not treated like a
   veteran with the same average: the policy uses a *pessimistic* score
   (mean minus one standard deviation), so trust is EARNED by track record.
3. Asymmetry. Bad outcomes carry much more weight than routine good ones,
   so trust is lost fast and rebuilt slowly.
4. Memory fades. Evidence decays over time (good behaviour half-life 14
   days, bad behaviour 45 days): old mistakes are gradually forgiven, but
   more slowly than old good deeds are forgotten.
5. Proportional credit. Completing a risky action safely earns more than
   reading a public file. Asking for review is never penalised.
6. Bursts escalate. Several bad events in a short window trigger an
   automatic quarantine (agents) or suspension (users), like fraud
   detection freezing a card.
"""
import math
from dataclasses import dataclass
from datetime import datetime

PRIORS = {"agent": (8.0, 2.0), "user": (8.0, 2.0)}  # both start at 0.80, low confidence
POS_HALF_LIFE_DAYS = 14.0
NEG_HALF_LIFE_DAYS = 45.0

TIERS = [  # (minimum pessimistic score, tier)
    (0.75, "trusted"),
    (0.55, "standard"),
    (0.35, "probation"),
    (0.0, "restricted"),
]

BURST_WINDOW_MIN = {"agent": 10, "user": 15}
BURST_COUNT = 3
BURST_LOCK_MIN = {"agent": 15, "user": 30}
CRITICAL_FLOOR = 0.25          # pessimistic score below this -> automatic lock
CRITICAL_LOCK_MIN = 60


@dataclass
class TrustView:
    mean: float
    lower: float          # pessimistic score used by the policy engine
    std: float
    evidence: float       # how much history supports the estimate
    tier: str
    positive: float
    negative: float

    def as_dict(self) -> dict:
        return {
            "mean": round(self.mean, 4),
            "lower": round(self.lower, 4),
            "std": round(self.std, 4),
            "evidence": round(self.evidence, 2),
            "tier": self.tier,
            "positive": round(self.positive, 3),
            "negative": round(self.negative, 3),
        }


def decay(value: float, days: float, half_life: float) -> float:
    return value * 0.5 ** (max(0.0, days) / half_life)


def decayed(pos: float, neg: float, updated_at: datetime | None, now: datetime) -> tuple[float, float]:
    if updated_at is None:
        return pos, neg
    days = (now - updated_at).total_seconds() / 86400
    return decay(pos, days, POS_HALF_LIFE_DAYS), decay(neg, days, NEG_HALF_LIFE_DAYS)


def tier_for(lower: float) -> str:
    for threshold, name in TIERS:
        if lower >= threshold:
            return name
    return "restricted"


def compute(kind: str, pos: float, neg: float) -> TrustView:
    a0, b0 = PRIORS[kind]
    a, b = a0 + pos, b0 + neg
    n = a + b
    mean = a / n
    std = math.sqrt((a * b) / (n * n * (n + 1)))
    lower = max(0.0, mean - std)
    return TrustView(mean, lower, std, pos + neg, tier_for(lower), pos, neg)


# ---------------- evidence weights (what each outcome is worth) ----------------

def agent_evidence_for_decision(
    decision: str, rule: str | None, risk: float, tool_ok: bool, tainted: bool, request_risk: float
) -> tuple[float, float, str]:
    """Returns (positive, negative, explanation) for one policy decision."""
    if decision == "ALLOW":
        if tool_ok:
            return 0.15 + 0.5 * risk, 0.0, f"Completed an allowed action safely (risk {risk:.2f})"
        return 0.0, 0.0, "Allowed action failed to execute (no trust change)"
    if decision == "REVIEW":
        return 0.0, 0.0, "Escalated for human review (asking permission is never penalised)"

    # DENY: how much is the agent to blame?
    base = {"not_in_allowlist": 2.0, "privileged_tool": 2.0, "critical_content": 1.5,
            "blocked_destination": 1.5}.get(rule or "", 0.75)
    blame = 1.0
    notes = []
    if tainted:
        blame *= 0.5
        notes.append("was manipulated by untrusted content")
    if request_risk >= 0.3:
        blame *= 0.4
        notes.append("user requested it")
    why = f"Attempted a denied action ({rule})" + (f"; reduced blame: {', '.join(notes)}" if notes else "")
    return 0.0, round(base * blame, 3), why


def user_evidence_for_decision(decision: str, tainted: bool) -> tuple[float, float, str]:
    if decision != "DENY":
        return 0.0, 0.0, ""
    if tainted:
        return 0.0, 0.1, "Supplied content that led to a denied action"
    return 0.0, 0.4, "Request led the agent to a denied action"


def user_evidence_for_request(request_score: float) -> tuple[float, float, str]:
    if request_score >= 0.7:
        return 0.0, round(2.0 * request_score, 3), "Message contained strong malicious-intent indicators"
    if request_score >= 0.4:
        return 0.0, 0.25, "Message contained a borderline request (e.g. bulk data movement)"
    return 0.0, 0.0, ""


USER_TASK_COMPLETED = (0.25, 0.0, "Completed a task with no policy violations")
APPROVAL_EVIDENCE = {
    "agent": {"APPROVE": (1.0, 0.0, "Human approved its escalated action"),
              "REJECT": (0.0, 1.5, "Human rejected its escalated action")},
    "user": {"APPROVE": (0.5, 0.0, "Human approved an action from their request"),
             "REJECT": (0.0, 1.0, "Human rejected an action from their request")},
}
