"""Poll credit consumption and attribute it to entities.

The consumption endpoint identifies users by display name and email, not by id,
and the identifiers it returns are inconsistent: some rows carry both ``email``
and ``userEmail``, some carry an address in ``name``, and some carry only a
display name. Attribution therefore goes through an explicit ladder of matches,
and anything that falls off the end is recorded in ``unresolved_subject`` rather
than dropped or guessed at.

Dimensions are probed once and the outcome remembered. ``viewBy=project`` is not
confirmed to exist on every tenant, and the difference between "this project used
zero credits" and "this tenant cannot report per project usage" decides whether it
is safe to enforce a project limit at all.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx import usage as usage_api
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import (
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxResponseError,
)
from app.db.base import utcnow
from app.models.enums import ActorType, EntityType, UsageView
from app.models.org import CxApplication, CxGroup, CxProject, CxUser
from app.models.usage import DimensionState, UnresolvedSubject, UsageRecord, UsageSnapshot
from app.services import subject_matching
from app.services.audit import AuditActor, record_audit
from app.services.subject_matching import MatchMethod, MatchOutcome, UserProfile

logger = logging.getLogger(__name__)

# Dimensions polled every cycle. ACTION is tenant wide totals for the dashboard
# breakdown; the other three feed limit evaluation.
DEFAULT_VIEWS: tuple[UsageView, ...] = (
    UsageView.USER,
    UsageView.ACTION,
    UsageView.APPLICATION,
    UsageView.PROJECT,
    UsageView.GROUP,
)

# Consumption the tenant attributes to automation rather than to a person. Auto
# Triage is reported in the *user* dimension under a synthetic name like
# "Auto-triage", which is not a user and must not be offered to an admin as an
# unmatched person to map. Per the brief it belongs to the project only, so it is
# counted tenant wide and at project level, and deliberately not at user level.
SYNTHETIC_SUBJECTS: frozenset[str] = frozenset(
    {
        "auto-triage",
        "auto triage",
        "autotriage",
        "auto_triage",
        "auto-remediation",
        "auto remediation",
        "system",
    }
)


def is_synthetic_subject(subject_key: str) -> bool:
    return subject_key.strip().lower() in SYNTHETIC_SUBJECTS


@dataclass
class DimensionResult:
    view_by: str
    supported: bool
    records: int = 0
    total_credits: Decimal = Decimal("0")
    # User rows not counted towards a limit: disputed plus unmatched, excluding
    # automation handles. These are what the "unmatched usage" banner surfaces.
    unresolved: int = 0
    # Rows the fuzzy matcher attributed automatically (and logged).
    auto_matched: int = 0
    # Plausible matches left for a human to confirm.
    disputed: int = 0
    # Rows attributed to automation rather than to a person, such as Auto Triage.
    automated: int = 0
    snapshot_id: int | None = None
    error: str | None = None


@dataclass
class IngestResult:
    dimensions: dict[str, DimensionResult] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_records(self) -> int:
        return sum(dimension.records for dimension in self.dimensions.values())

    def as_stats(self) -> dict[str, object]:
        return {
            view: {
                "supported": dimension.supported,
                "records": dimension.records,
                "credits": str(dimension.total_credits),
                "unresolved": dimension.unresolved,
                "auto_matched": dimension.auto_matched,
                "disputed": dimension.disputed,
                "automated": dimension.automated,
                "error": dimension.error,
            }
            for view, dimension in self.dimensions.items()
        }


# ------------------------------------------------------------------- resolution


@dataclass(frozen=True, slots=True)
class UserIndex:
    """Everything needed to match a consumption row to a synced IAM user."""

    by_email: dict[str, str]
    by_username: dict[str, str]
    by_full_name: dict[str, str]
    ambiguous_full_names: frozenset[str]
    pinned: dict[str, str]
    # Token profiles for the fuzzy fall-through, one per synced user.
    profiles: tuple[UserProfile, ...] = ()

    def _resolve_exact(
        self, *, subject_key: str, name: str | None, email: str | None
    ) -> str | None:
        """The deterministic ladder: email, then username, then unambiguous name.

        Full name is last and only when unambiguous: two people called
        "Sean Casey" must not have one budget between them.
        """
        for candidate in (email, name):
            if candidate and usage_api.looks_like_email(candidate):
                found = self.by_email.get(candidate.strip().lower())
                if found:
                    return found
        if name:
            key = name.strip().lower()
            found = self.by_username.get(key)
            if found:
                return found
            if key not in self.ambiguous_full_names:
                found = self.by_full_name.get(key)
                if found:
                    return found
        return None

    def resolve_detailed(
        self, *, subject_key: str, name: str | None, email: str | None
    ) -> MatchOutcome:
        """Full attribution decision: pin, then exact ladder, then fuzzy triage."""
        pinned = self.pinned.get(subject_key)
        if pinned:
            return MatchOutcome(MatchMethod.PINNED, pinned)
        exact = self._resolve_exact(subject_key=subject_key, name=name, email=email)
        if exact:
            return MatchOutcome(MatchMethod.EXACT, exact)
        return subject_matching.classify(
            subject_key=subject_key, name=name, email=email, profiles=self.profiles
        )


def build_user_index(session: Session) -> UserIndex:
    by_email: dict[str, str] = {}
    by_username: dict[str, str] = {}
    by_full_name: dict[str, str] = {}
    duplicates: set[str] = set()
    profiles: list[UserProfile] = []

    for user in session.scalars(select(CxUser).where(CxUser.is_deleted.is_(False))):
        if user.email:
            by_email[user.email.strip().lower()] = user.id
        if user.username:
            by_username[user.username.strip().lower()] = user.id
            # Usernames are often email addresses in Checkmarx One.
            if usage_api.looks_like_email(user.username):
                by_email.setdefault(user.username.strip().lower(), user.id)
        full_name = " ".join(part for part in (user.first_name, user.last_name) if part).strip()
        if full_name:
            key = full_name.lower()
            if key in by_full_name and by_full_name[key] != user.id:
                duplicates.add(key)
            by_full_name[key] = user.id

        # One token set per user, drawn from every identifier they carry, so the
        # fuzzy matcher can compare a handle against name and email at once.
        tokens = subject_matching.tokenize(
            full_name or None, user.email, user.username, user.first_name, user.last_name
        )
        if tokens:
            profiles.append(UserProfile(user_id=user.id, label=user.display_name, tokens=tokens))

    for key in duplicates:
        by_full_name.pop(key, None)

    pinned = {
        row.subject_key: row.mapped_user_id
        for row in session.scalars(
            select(UnresolvedSubject).where(UnresolvedSubject.mapped_user_id.is_not(None))
        )
        if row.mapped_user_id
    }
    return UserIndex(
        by_email=by_email,
        by_username=by_username,
        by_full_name=by_full_name,
        ambiguous_full_names=frozenset(duplicates),
        pinned=pinned,
        profiles=tuple(profiles),
    )


def _named_index(session: Session, model) -> tuple[dict[str, str], dict[str, str]]:
    """(by id, by lowercased name) for projects or applications."""
    by_id: dict[str, str] = {}
    by_name: dict[str, str] = {}
    for row in session.scalars(select(model).where(model.is_deleted.is_(False))):
        by_id[row.id] = row.id
        if row.name:
            by_name.setdefault(row.name.strip().lower(), row.id)
    return by_id, by_name


# -------------------------------------------------------------------- ingestion


def ingest_usage(
    session: Session,
    client: CheckmarxClient,
    *,
    period_param: str = usage_api.DEFAULT_PERIOD,
    page_size: int = usage_api.DEFAULT_PAGE_SIZE,
    views: tuple[UsageView, ...] = DEFAULT_VIEWS,
) -> IngestResult:
    result = IngestResult()
    user_index = build_user_index(session)
    projects_by_id, projects_by_name = _named_index(session, CxProject)
    apps_by_id, apps_by_name = _named_index(session, CxApplication)
    groups_by_id, groups_by_name = _named_index(session, CxGroup)

    # Fetched at most once per run, and only if a dimension's support is still
    # unknown. See _confirm_not_a_fallback for why this is necessary.
    fallback_fingerprint: frozenset[str] | None = None
    fallback_probed = False

    for view in views:
        state = session.get(DimensionState, str(view))
        if state is not None and state.supported is False:
            result.dimensions[str(view)] = DimensionResult(
                view_by=str(view), supported=False, error=state.last_error
            )
            continue

        # USER is the dimension the endpoint falls back to, so it can never be a
        # false positive and needs no probe.
        if state is None and view != UsageView.USER and not fallback_probed:
            fallback_fingerprint = usage_api.fetch_fallback_fingerprint(
                client, period=period_param, page_size=page_size
            )
            fallback_probed = True

        try:
            dimension = _ingest_dimension(
                session,
                client,
                view=view,
                period_param=period_param,
                page_size=page_size,
                user_index=user_index,
                projects_by_id=projects_by_id,
                projects_by_name=projects_by_name,
                apps_by_id=apps_by_id,
                apps_by_name=apps_by_name,
                groups_by_id=groups_by_id,
                groups_by_name=groups_by_name,
                fallback_fingerprint=fallback_fingerprint if state is None else None,
            )
        except FallbackDetected as exc:
            # The endpoint answered 200 but gave us the user dimension instead of the
            # one we asked for. Treating that as real data would attribute one
            # entity's consumption to another.
            message = str(exc)
            _record_dimension(session, view, supported=False, error=message)
            dimension = DimensionResult(view_by=str(view), supported=False, error=message)
            result.warnings.append(
                f"Checkmarx does not report consumption by {view} on this tenant. It "
                f"answered successfully but returned the user view instead, so that "
                f"dimension is ignored. Limits at that level are not evaluated."
            )
            logger.warning("Dimension %s is a silent fallback to the user view", view)
        except (CheckmarxNotFoundError, CheckmarxResponseError) as exc:
            # A 4xx on one dimension means the tenant does not offer it. Record
            # that once and stop asking, rather than failing the whole cycle.
            message = str(exc)
            _record_dimension(session, view, supported=False, error=message)
            dimension = DimensionResult(view_by=str(view), supported=False, error=message)
            result.warnings.append(
                f"Checkmarx does not report consumption by {view}: {message} "
                f"Limits at that level cannot be evaluated."
            )
            logger.warning("Consumption dimension %s is unavailable: %s", view, message)
        except CheckmarxPermissionError as exc:
            message = str(exc)
            _record_dimension(session, view, supported=None, error=message)
            dimension = DimensionResult(view_by=str(view), supported=False, error=message)
            result.warnings.append(
                f"The API key is not permitted to read consumption by {view}. {message}"
            )
        else:
            _record_dimension(session, view, supported=True, error=None)

        result.dimensions[str(view)] = dimension

    session.flush()
    return result


def _record_dimension(
    session: Session, view: UsageView, *, supported: bool | None, error: str | None
) -> None:
    state = session.get(DimensionState, str(view))
    if state is None:
        state = DimensionState(view_by=str(view))
        session.add(state)
    state.supported = supported
    state.last_error = error[:2000] if error else None
    state.last_checked_at = utcnow()
    session.flush()


class FallbackDetected(RuntimeError):
    """The endpoint returned the user view for a dimension we asked for by name."""


def _ingest_dimension(
    session: Session,
    client: CheckmarxClient,
    *,
    view: UsageView,
    period_param: str,
    page_size: int,
    user_index: UserIndex,
    projects_by_id: dict[str, str],
    projects_by_name: dict[str, str],
    apps_by_id: dict[str, str],
    apps_by_name: dict[str, str],
    groups_by_id: dict[str, str] | None = None,
    groups_by_name: dict[str, str] | None = None,
    fallback_fingerprint: frozenset[str] | None = None,
) -> DimensionResult:
    now = utcnow()
    snapshot = UsageSnapshot(collected_at=now, view_by=str(view), period_param=period_param, raw=[])
    session.add(snapshot)
    session.flush()

    raw_pages: list[dict] = []
    merged: dict[str, usage_api.ParsedUsageItem] = {}
    total_items: int | None = None
    pages = 0

    for page in usage_api.fetch_usage(
        client, view_by=view, period=period_param, page_size=page_size
    ):
        pages += 1
        if page.raw is not None:
            raw_pages.append(page.raw)
        if page.total_items is not None:
            total_items = page.total_items
        for item in page.items:
            existing = merged.get(item.subject_key)
            if existing is None:
                merged[item.subject_key] = item
            else:
                # The same subject appearing on two pages would otherwise be
                # overwritten rather than combined.
                merged[item.subject_key] = _combine(existing, item)

    # Compare against the deliberate bad-parameter probe before storing anything. An
    # identical subject set means this dimension does not exist and we were handed the
    # user view, which would otherwise be filed as project or application usage.
    # Both sides must be non empty: two empty responses are identical without
    # telling us anything, and a real but idle dimension legitimately returns none.
    if fallback_fingerprint and merged and frozenset(merged.keys()) == fallback_fingerprint:
        session.delete(snapshot)
        session.flush()
        raise FallbackDetected(
            f"viewBy={view} returned the same subjects as an unrecognised viewBy "
            "value, so the endpoint silently fell back to the user dimension."
        )

    snapshot.raw = raw_pages
    snapshot.total_items = total_items
    snapshot.pages_fetched = pages

    result = DimensionResult(view_by=str(view), supported=True, snapshot_id=snapshot.id)
    total = Decimal("0")

    for item in merged.values():
        outcome: MatchOutcome | None = None
        if view == UsageView.USER:
            outcome = user_index.resolve_detailed(
                subject_key=item.subject_key, name=item.subject_name, email=item.subject_email
            )
            entity_type, entity_id = EntityType.USER, outcome.counted_user_id
        else:
            entity_type, entity_id = _attribute(
                view=view,
                item=item,
                projects_by_id=projects_by_id,
                projects_by_name=projects_by_name,
                apps_by_id=apps_by_id,
                apps_by_name=apps_by_name,
                groups_by_id=groups_by_id or {},
                groups_by_name=groups_by_name or {},
            )
        session.add(
            UsageRecord(
                snapshot_id=snapshot.id,
                view_by=str(view),
                subject_key=item.subject_key[:320],
                subject_name=item.subject_name,
                subject_email=item.subject_email,
                entity_type=entity_type,
                entity_id=entity_id,
                credits_used=item.credits_used,
                percent_of_total=item.percent_of_total,
                transactions=item.transactions,
                actions=item.actions or None,
                raw=item.raw,
            )
        )
        total += item.credits_used
        result.records += 1

        if view == UsageView.USER and outcome is not None:
            # A synthetic subject such as "Auto-triage" is automation, not a
            # person. It is stored and counted tenant wide, but never offered as
            # an unmatched user and never attributed to a user limit.
            if is_synthetic_subject(item.subject_key):
                result.automated += 1
            else:
                _apply_user_outcome(session, item, outcome, now, result)

    snapshot.total_credits = total
    result.total_credits = total
    session.flush()
    return result


def _combine(
    first: usage_api.ParsedUsageItem, second: usage_api.ParsedUsageItem
) -> usage_api.ParsedUsageItem:
    actions = dict(first.actions)
    for action, count in second.actions.items():
        actions[action] = actions.get(action, 0) + count
    from dataclasses import replace

    return replace(
        first,
        credits_used=first.credits_used + second.credits_used,
        transactions=(first.transactions or 0) + (second.transactions or 0),
        actions=actions,
    )


def _attribute(
    *,
    view: UsageView,
    item: usage_api.ParsedUsageItem,
    projects_by_id: dict[str, str],
    projects_by_name: dict[str, str],
    apps_by_id: dict[str, str],
    apps_by_name: dict[str, str],
    groups_by_id: dict[str, str],
    groups_by_name: dict[str, str],
) -> tuple[str | None, str | None]:
    """Attribute a non-user dimension. The user dimension is resolved inline so
    its full match outcome (auto-match, dispute, suggestions) can be recorded."""
    if view == UsageView.APPLICATION:
        found = _match_named(item, apps_by_id, apps_by_name)
        return EntityType.APPLICATION, found

    if view == UsageView.PROJECT:
        found = _match_named(item, projects_by_id, projects_by_name)
        return EntityType.PROJECT, found

    if view == UsageView.GROUP:
        # Unmatched is expected rather than exceptional here: the row shape for this
        # dimension has not been observed with data, so evaluation falls back to
        # rolling up the group's projects when nothing matches.
        found = _match_named(item, groups_by_id, groups_by_name)
        return EntityType.GROUP, found

    # The action dimension is tenant wide, so it has no entity.
    return None, None


def _match_named(
    item: usage_api.ParsedUsageItem, by_id: dict[str, str], by_name: dict[str, str]
) -> str | None:
    if item.reported_id and item.reported_id in by_id:
        return item.reported_id
    if item.subject_name:
        return by_name.get(item.subject_name.strip().lower())
    return None


def _apply_user_outcome(
    session: Session,
    item: usage_api.ParsedUsageItem,
    outcome: MatchOutcome,
    now,
    result: DimensionResult,
) -> None:
    """Record the review state for one user subject and bump the run counters.

    A cleanly resolved subject (exact match) needs no review row, so any stale
    one it left behind is removed. Everything else - an automatic fuzzy match, a
    dispute or a plain miss - is upserted so it can be shown and overridden.
    """
    row = session.scalar(
        select(UnresolvedSubject).where(UnresolvedSubject.subject_key == item.subject_key)
    )

    if outcome.method in (MatchMethod.PINNED, MatchMethod.EXACT):
        # Now resolved for real. Drop a lingering review row unless an admin
        # pinned it (that mapping is the resolution and must stay).
        if row is not None and row.mapped_user_id is None:
            session.delete(row)
        return

    if outcome.method == MatchMethod.FUZZY_AUTO:
        result.auto_matched += 1
    elif outcome.method == MatchMethod.DISPUTED:
        result.disputed += 1
        result.unresolved += 1
    elif not outcome.is_bot:
        # A plain miss still counts towards the unmatched banner; a bot does not.
        result.unresolved += 1

    top = outcome.candidates[0] if outcome.candidates else None
    suggestions = [candidate.as_dict() for candidate in outcome.candidates]

    # A newly established (or retargeted) auto-match is worth one audit entry;
    # an unchanged one is not, or a steady state would re-log every cycle.
    newly_auto = (
        outcome.method == MatchMethod.FUZZY_AUTO
        and top is not None
        and (
            row is None
            or row.status != MatchMethod.FUZZY_AUTO
            or row.suggested_user_id != top.user_id
        )
    )

    if row is None:
        session.add(
            UnresolvedSubject(
                subject_key=item.subject_key[:320],
                subject_name=item.subject_name,
                subject_email=item.subject_email,
                view_by=UsageView.USER,
                credits_used=item.credits_used,
                first_seen_at=now,
                last_seen_at=now,
                times_seen=1,
                status=outcome.method,
                is_bot=outcome.is_bot,
                suggested_user_id=top.user_id if top else None,
                match_score=top.score if top else None,
                suggestions=suggestions or None,
            )
        )
    else:
        row.last_seen_at = now
        row.times_seen += 1
        row.credits_used = item.credits_used
        if item.subject_email and not row.subject_email:
            row.subject_email = item.subject_email
        row.status = outcome.method
        row.is_bot = outcome.is_bot
        row.suggested_user_id = top.user_id if top else None
        row.match_score = top.score if top else None
        row.suggestions = suggestions or None

    if newly_auto and top is not None:
        record_audit(
            session,
            action="usage.subject_auto_matched",
            actor=AuditActor(actor_type=ActorType.SYSTEM, actor_name="matcher"),
            target_type="unresolved_subject",
            target_id=item.subject_key[:64],
            target_label=item.subject_key,
            after={"suggested_user_id": top.user_id, "score": round(top.score, 4)},
            detail=(
                f"Credit usage reported as {item.subject_key} was automatically matched to "
                f"{top.label} at {round(top.score * 100)}% confidence. Override it on the "
                "Settings page if this is wrong."
            ),
        )


# ------------------------------------------------------------------ reading back


def latest_snapshot(session: Session, view: UsageView | str) -> UsageSnapshot | None:
    return session.scalar(
        select(UsageSnapshot)
        .where(UsageSnapshot.view_by == str(view))
        .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
        .limit(1)
    )


def latest_totals(session: Session, view: UsageView | str) -> dict[str, Decimal]:
    """Reported credit totals keyed by resolved entity id, from the newest snapshot."""
    snapshot = latest_snapshot(session, view)
    if snapshot is None:
        return {}
    rows = session.execute(
        select(UsageRecord.entity_id, func.sum(UsageRecord.credits_used))
        .where(
            UsageRecord.snapshot_id == snapshot.id,
            UsageRecord.entity_id.is_not(None),
        )
        .group_by(UsageRecord.entity_id)
    ).all()
    return {entity_id: Decimal(str(total or 0)) for entity_id, total in rows if entity_id}


def dimension_supported(session: Session, view: UsageView | str) -> bool:
    """True unless a probe has positively established that the dimension is absent."""
    state = session.get(DimensionState, str(view))
    return True if state is None else state.supported is not False
