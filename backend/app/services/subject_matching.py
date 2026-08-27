"""Fuzzy attribution of consumption subjects to synced Checkmarx users.

The consumption feed identifies a user by whatever string the action was
reported under. Most rows carry a clean email or display name that the exact
ladder in :mod:`app.services.ingestion` resolves. What is left over is the messy
tail the exact ladder cannot touch: service-style handles such as
``cx-ryan-wakeham`` for *Ryan Wakeham*, a bare email local part, a first name on
its own, or a small typo. Left unmatched these credits count towards nobody's
limit, which is exactly the usage a limit is meant to catch.

This module turns both sides into a normalised *token set* and scores them, so
``cx-ryan-wakeham`` and ``ryan.wakeham@checkmarx.com`` land on the same
``{ryan, wakeham}`` and match at full confidence. The score drives a three-way
decision, deliberately conservative because a wrong auto-match silently bills the
wrong person:

* ``>= AUTO_MATCH_THRESHOLD`` and unambiguous -> attributed automatically and
  logged, still overridable by an admin.
* ``>= DISPUTE_THRESHOLD`` (or an auto-worthy near-tie between two people) ->
  left uncounted and surfaced as a *dispute* with ranked suggestions for a
  human to confirm.
* below that -> unmatched, as before.

The functions here are pure and hold no database or network state, so the whole
policy is unit-testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

# Score at or above which a single clear best candidate is attributed
# automatically. High on purpose: auto-attribution moves someone's credits.
AUTO_MATCH_THRESHOLD = 0.85
# Score at or above which a candidate is worth a human's attention as a
# suggestion, even though it is not confident enough to apply on its own.
DISPUTE_THRESHOLD = 0.60
# Two candidates whose scores sit within this margin are treated as a tie: even
# above the auto threshold the row is disputed rather than guessed.
AMBIGUITY_MARGIN = 0.05
# How many ranked suggestions to keep for a disputed or auto-matched subject.
MAX_SUGGESTIONS = 5

# Leading connector prefixes stripped from a handle before comparison, so
# ``cx-ryan-wakeham`` compares as ``ryan wakeham``.
_PREFIX_TOKENS = frozenset({"cx", "svc", "srv"})

# Handles that are automation rather than people. Matched exactly (or on the
# email local part), never as a substring, so a real user called "Abbot" is
# never mistaken for a bot.
_BOT_NAMES = frozenset(
    {
        "dependabot",
        "dependabot[bot]",
        "renovate",
        "renovate[bot]",
        "github-actions",
        "github-actions[bot]",
        "snyk-bot",
        "codecov",
        "codecov[bot]",
        "mergify",
        "mergify[bot]",
        "greenkeeper",
    }
)


class MatchMethod:
    """How a subject was attributed. Stored verbatim on ``unresolved_subject``."""

    PINNED = "pinned"  # an admin mapped it by hand; always wins
    EXACT = "exact"  # resolved by the deterministic email/username/name ladder
    FUZZY_AUTO = "auto_matched"  # confidently matched by similarity, and logged
    DISPUTED = "disputed"  # a plausible match a human should confirm
    UNMATCHED = "unmatched"  # nothing crossed the dispute threshold


# Statuses that are recorded on ``unresolved_subject`` for review. PINNED and
# EXACT need no review row, so they never appear here.
REVIEW_STATUSES = frozenset({MatchMethod.FUZZY_AUTO, MatchMethod.DISPUTED, MatchMethod.UNMATCHED})


@dataclass(frozen=True, slots=True)
class Candidate:
    """One ranked user a subject might belong to."""

    user_id: str
    label: str
    score: float

    def as_dict(self) -> dict[str, object]:
        return {"user_id": self.user_id, "label": self.label, "score": round(self.score, 4)}


@dataclass(frozen=True, slots=True)
class UserProfile:
    """A synced user reduced to the token set used for matching."""

    user_id: str
    label: str
    tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class MatchOutcome:
    """The result of classifying one subject."""

    method: str
    user_id: str | None
    candidates: tuple[Candidate, ...] = ()
    is_bot: bool = False

    @property
    def counted_user_id(self) -> str | None:
        """The user this subject's credits count towards, if any."""
        if self.method in (MatchMethod.PINNED, MatchMethod.EXACT, MatchMethod.FUZZY_AUTO):
            return self.user_id
        return None


def _split_tokens(value: str) -> list[str]:
    """Lowercase, take an email local part, and split on any non-alphanumeric run."""
    text = value.strip().lower()
    if text.count("@") == 1 and " " not in text:
        text = text.split("@", 1)[0]
    token = ""
    tokens: list[str] = []
    for char in text:
        if char.isalnum():
            token += char
        elif token:
            tokens.append(token)
            token = ""
    if token:
        tokens.append(token)
    return tokens


def tokenize(*values: str | None) -> frozenset[str]:
    """Turn one or more identity strings into a comparable token set.

    Drops a leading connector prefix (``cx``) and single-character noise, so
    ``cx-ryan-wakeham``, ``Ryan Wakeham`` and ``ryan.wakeham@checkmarx.com`` all
    reduce to ``{ryan, wakeham}``.
    """
    collected: set[str] = set()
    for value in values:
        if not value:
            continue
        parts = _split_tokens(value)
        # Strip a single leading connector prefix such as "cx".
        if parts and parts[0] in _PREFIX_TOKENS:
            parts = parts[1:]
        for part in parts:
            if len(part) >= 2:
                collected.add(part)
    return frozenset(collected)


def is_bot_subject(*values: str | None) -> bool:
    """True when the subject is an automation account rather than a person."""
    for value in values:
        if not value:
            continue
        low = value.strip().lower()
        if "[bot]" in low:
            return True
        if low in _BOT_NAMES:
            return True
        local = low.split("@", 1)[0] if "@" in low else low
        if local in _BOT_NAMES:
            return True
    return False


def similarity(a: frozenset[str], b: frozenset[str]) -> float:
    """Similarity of two token sets in ``[0, 1]``.

    Blends token overlap (order-independent, so "Wakeham Ryan" matches "Ryan
    Wakeham") with a character-level ratio that rescues typos and nicknames
    ("mathew" vs "matthew"). The larger of the two wins, so either signal alone
    is enough.
    """
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    inter = a & b
    if inter:
        overlap = len(inter) / min(len(a), len(b))
        jaccard = len(inter) / len(a | b)
        token_score = 0.6 * overlap + 0.4 * jaccard
    else:
        token_score = 0.0

    ratio = SequenceMatcher(None, " ".join(sorted(a)), " ".join(sorted(b))).ratio()
    return max(token_score, ratio)


def rank_candidates(
    subject_tokens: frozenset[str], profiles: tuple[UserProfile, ...]
) -> list[Candidate]:
    """Users scored against the subject, best first, keeping only plausible ones."""
    scored = [
        Candidate(user_id=profile.user_id, label=profile.label, score=score)
        for profile in profiles
        if (score := similarity(subject_tokens, profile.tokens)) >= DISPUTE_THRESHOLD
    ]
    # Sort by score, then label, so the order is stable across cycles for a tie.
    scored.sort(key=lambda candidate: (-candidate.score, candidate.label))
    return scored[:MAX_SUGGESTIONS]


def classify(
    *,
    subject_key: str,
    name: str | None,
    email: str | None,
    profiles: tuple[UserProfile, ...],
) -> MatchOutcome:
    """Decide how a still-unresolved subject should be attributed."""
    if is_bot_subject(subject_key, name, email):
        return MatchOutcome(MatchMethod.UNMATCHED, None, (), is_bot=True)

    subject_tokens = tokenize(subject_key, name, email)
    if not subject_tokens:
        return MatchOutcome(MatchMethod.UNMATCHED, None, ())

    candidates = tuple(rank_candidates(subject_tokens, profiles))
    if not candidates:
        return MatchOutcome(MatchMethod.UNMATCHED, None, ())

    top = candidates[0]
    if top.score < AUTO_MATCH_THRESHOLD:
        return MatchOutcome(MatchMethod.DISPUTED, None, candidates)
    # Confident enough to apply, unless a second person is almost as good a fit:
    # a near-tie must never be resolved silently to one budget.
    if len(candidates) > 1 and top.score - candidates[1].score < AMBIGUITY_MARGIN:
        return MatchOutcome(MatchMethod.DISPUTED, None, candidates)
    return MatchOutcome(MatchMethod.FUZZY_AUTO, top.user_id, candidates)
