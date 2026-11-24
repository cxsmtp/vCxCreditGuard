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
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from app.checkmarx import usage as usage_api
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import (
    CheckmarxError,
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxResponseError,
)
from app.db.base import utcnow
from app.models.enums import ActorType, EntityType, UsageView
from app.models.org import CxApplication, CxGroup, CxProject, CxUser
from app.models.usage import (
    DimensionState,
    EntityMapping,
    UnresolvedSubject,
    UsageAnchor,
    UsageRecord,
    UsageSnapshot,
)
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
# unmatched person to map. It is counted tenant wide and at project level, and
# never at user level from this row. (With the setting
# attribution.auto_triage_to_scan_initiator on, the project's auto-triage credits
# are additionally charged to whoever started the scan, from the scan listing:
# see app/services/auto_triage_attribution.py. This row still counts for nobody.)
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


# A dimension found unavailable is asked for again after this long. Tenants gain
# features, and one odd answer must not switch a dimension off for good.
REPROBE_UNSUPPORTED_AFTER = timedelta(hours=24)

# A read whose total is below this share of the previous read is not believed
# straight away. Reported consumption only falls when old usage ages out of the
# lookback window, which is gradual; a collapse is far more often an API hiccup
# (an empty or partial answer with a 200). Believing it would wipe every period
# baseline, lift every restriction, and then restrict everyone again in one go
# when the real figures came back.
HOLD_DROP_RATIO = Decimal("0.5")
# ...unless the collapse persists: at least this many reads in a row, spanning at
# least this long, all telling the same story. Then it is taken as real (a
# genuine reset, such as a new subscription term). Both conditions matter: with a
# two minute schedule, three reads alone would be only minutes of protection.
HOLD_CONFIRMATIONS = 3
HOLD_MIN_DURATION = timedelta(hours=2)


class UsageIncompleteError(CheckmarxError):
    """Pagination stopped before the endpoint's own page count was reached."""


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
    # Rows attributed to automation rather than to a person: Auto Triage and
    # other synthetic subjects, bots ("[bot]") and integration identities (a
    # handle with no email that matches nobody). Counted tenant wide, towards
    # no user limit, and never raised as an unmatched person.
    automated: int = 0
    automated_credits: Decimal = Decimal("0")
    # Project/application/group rows that matched no synced entity (by id, by
    # name, or by an admin's mapping), and their credits. On a live tenant most
    # project credits were reported under "org/repo" names that are no project.
    unmatched_entities: int = 0
    unmatched_credits: Decimal = Decimal("0")
    snapshot_id: int | None = None
    error: str | None = None
    # True when the read was stored as evidence but not believed (see
    # HOLD_DROP_RATIO); evaluation keeps using the previous snapshot.
    held: bool = False
    # True when the dimension should have been readable and was not (an outage, a
    # truncated answer, a permission problem), as opposed to the tenant simply
    # not offering it.
    read_failed: bool = False


@dataclass
class IngestResult:
    dimensions: dict[str, DimensionResult] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # Dimensions that could not be read this cycle for a reason that is expected
    # to pass (outage, rate limit, truncated answer). Evaluation then runs on the
    # previous snapshot, and the cycle is reported as partial.
    errors: list[str] = field(default_factory=list)

    @property
    def fresh(self) -> bool:
        """True when every dimension that feeds limits was read and believed.

        The action dimension only feeds the dashboard breakdown, so a problem
        there does not make the figures limits are judged on stale.
        """
        return not any(
            dimension.held or dimension.read_failed
            for view, dimension in self.dimensions.items()
            if view != str(UsageView.ACTION)
        )

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
                "automated_credits": str(dimension.automated_credits),
                "unmatched_entities": dimension.unmatched_entities,
                "unmatched_credits": str(dimension.unmatched_credits),
                "error": dimension.error,
                "held": dimension.held,
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
        "Bob Baker" must not have one budget between them.
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
        self,
        *,
        subject_key: str,
        name: str | None,
        email: str | None,
        integrations: bool = False,
    ) -> MatchOutcome:
        """Full attribution decision: pin, then exact ladder, then fuzzy triage.

        ``integrations``: an unmatched handle with no email is automation (a
        consumption row; see subject_matching.is_integration_identity).
        """
        pinned = self.pinned.get(subject_key)
        if pinned:
            return MatchOutcome(MatchMethod.PINNED, pinned)
        exact = self._resolve_exact(subject_key=subject_key, name=name, email=email)
        if exact:
            return MatchOutcome(MatchMethod.EXACT, exact)
        return subject_matching.classify(
            subject_key=subject_key,
            name=name,
            email=email,
            profiles=self.profiles,
            integrations=integrations,
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

    pinned = _pinned_users(session)
    return UserIndex(
        by_email=by_email,
        by_username=by_username,
        by_full_name=by_full_name,
        ambiguous_full_names=frozenset(duplicates),
        pinned=pinned,
        profiles=tuple(profiles),
    )


def _pinned_users(session: Session) -> dict[str, str]:
    """An admin's user mappings: {reported subject: user id}."""
    return {
        row.subject_key: row.mapped_user_id
        for row in session.scalars(
            select(UnresolvedSubject).where(UnresolvedSubject.mapped_user_id.is_not(None))
        )
        if row.mapped_user_id
    }


def _named_index(
    session: Session, model, mappings: dict[str, str] | None = None
) -> tuple[dict[str, str], dict[str, str]]:
    """(by id, by lowercased name) for projects or applications.

    ``mappings`` are an admin's (reported name -> entity id) for names that
    match no entity, from Settings → Attribution; a real name match wins, and
    a mapping to an entity that is gone is ignored.
    """
    by_id: dict[str, str] = {}
    by_name: dict[str, str] = {}
    for row in session.scalars(select(model).where(model.is_deleted.is_(False))):
        by_id[row.id] = row.id
        if row.name:
            by_name.setdefault(row.name.strip().lower(), row.id)
    for reported, entity_id in (mappings or {}).items():
        if entity_id in by_id:
            by_name.setdefault(reported.strip().lower(), entity_id)
    return by_id, by_name


def entity_mappings(session: Session) -> dict[str, dict[str, str]]:
    """An admin's mappings of unmatched names: {"project": {name: id}, ...}."""
    mappings: dict[str, dict[str, str]] = {}
    for row in session.scalars(select(EntityMapping).order_by(EntityMapping.id)):
        mappings.setdefault(row.view_by, {})[row.subject_key] = row.entity_id
    return mappings


def unresolved_person_filter() -> tuple:
    """The rows of ``unresolved_subject`` that are an unmatched *person*.

    One definition for every page and message: not mapped by an admin, not
    auto-matched (those credits count towards a user), not automation (a bot,
    an integration identity), and not a scan initiator (the auto-triage step
    raises those in its own words).
    """
    from app.services.auto_triage_attribution import SOURCE_SCAN_INITIATOR

    return (
        UnresolvedSubject.mapped_user_id.is_(None),
        UnresolvedSubject.status != MatchMethod.FUZZY_AUTO,
        UnresolvedSubject.is_bot.is_(False),
        UnresolvedSubject.view_by != SOURCE_SCAN_INITIATOR,
    )


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
    mappings = entity_mappings(session)
    projects_by_id, projects_by_name = _named_index(
        session, CxProject, mappings.get(str(UsageView.PROJECT))
    )
    apps_by_id, apps_by_name = _named_index(
        session, CxApplication, mappings.get(str(UsageView.APPLICATION))
    )
    groups_by_id, groups_by_name = _named_index(session, CxGroup)

    # Fetched at most once per run, and only if a dimension's support is still
    # unknown. See _confirm_not_a_fallback for why this is necessary.
    fallback_fingerprint: frozenset[str] | None = None
    fallback_probed = False

    for view in views:
        state = session.get(DimensionState, str(view))
        if (
            state is not None
            and state.supported is False
            and view != UsageView.USER
            and not _reprobe_due(state)
        ):
            result.dimensions[str(view)] = DimensionResult(
                view_by=str(view), supported=False, error=state.last_error
            )
            continue

        # Only a dimension that has answered properly before is trusted without a
        # probe. USER is the dimension the endpoint falls back to, so it can never
        # be a false positive and needs none.
        confirmed = state is not None and state.supported is True
        # Already known to be unavailable: a re-probe that finds it still
        # unavailable is not news, and must not degrade the run every day.
        known_unsupported = state is not None and state.supported is False
        # Nothing is left open in the database while we wait on Checkmarx.
        session.commit()
        if not confirmed and view != UsageView.USER and not fallback_probed:
            fallback_fingerprint = usage_api.fetch_fallback_fingerprint(
                client, period=period_param, page_size=page_size
            )
            fallback_probed = True

        if not confirmed and view != UsageView.USER and fallback_fingerprint is None:
            # The probe that tells a real dimension from a silent fallback to the
            # user view did not answer. Reading the dimension without it could
            # file one entity's usage under another and mark the dimension as
            # supported for good, so it is left for the next cycle.
            message = (
                f"Consumption by {view} could not be verified this cycle (the check for "
                "a silent fallback to the user view did not answer)."
            )
            result.dimensions[str(view)] = DimensionResult(
                view_by=str(view),
                supported=not known_unsupported,
                error=state.last_error if known_unsupported and state else message,
                read_failed=not known_unsupported,
            )
            if not known_unsupported:
                result.errors.append(message)
            continue

        try:
            fetched = _fetch_dimension(
                client,
                view=view,
                period_param=period_param,
                page_size=page_size,
                fallback_fingerprint=None if confirmed else fallback_fingerprint,
            )
            dimension = _store_dimension(
                session,
                fetched,
                view=view,
                period_param=period_param,
                user_index=user_index,
                projects_by_id=projects_by_id,
                projects_by_name=projects_by_name,
                apps_by_id=apps_by_id,
                apps_by_name=apps_by_name,
                groups_by_id=groups_by_id,
                groups_by_name=groups_by_name,
            )
            if dimension.held:
                result.warnings.append(dimension.error or f"The {view} read was held back.")
            _record_dimension(session, view, supported=True, error=None)
        except FallbackDetected as exc:
            # The endpoint answered 200 but gave us the user dimension instead of the
            # one we asked for. Treating that as real data would attribute one
            # entity's consumption to another.
            session.rollback()
            message = str(exc)
            _record_dimension(session, view, supported=False, error=message)
            dimension = DimensionResult(view_by=str(view), supported=False, error=message)
            if not known_unsupported:
                result.warnings.append(
                    f"Checkmarx does not report consumption by {view} on this tenant. It "
                    f"answered successfully but returned the user view instead, so that "
                    f"dimension is ignored. Limits at that level are not evaluated."
                )
                logger.warning("Dimension %s is a silent fallback to the user view", view)
        except (CheckmarxNotFoundError, CheckmarxResponseError) as exc:
            session.rollback()
            message = str(exc)
            if view == UsageView.USER:
                # The user dimension is the one everything else depends on, so it
                # is never written off: an odd answer is a failed read, retried
                # on the next cycle.
                _record_dimension(session, view, supported=None, error=message)
                dimension = DimensionResult(
                    view_by=str(view), supported=True, error=message, read_failed=True
                )
                result.errors.append(f"consumption by {view} could not be read: {message}")
            else:
                # A 4xx on one dimension means the tenant does not offer it.
                # Record that and stop asking for a while, rather than failing
                # the whole cycle.
                _record_dimension(session, view, supported=False, error=message)
                dimension = DimensionResult(view_by=str(view), supported=False, error=message)
                if not known_unsupported:
                    result.warnings.append(
                        f"Checkmarx does not report consumption by {view}: {message} "
                        f"Limits at that level cannot be evaluated."
                    )
            if not known_unsupported:
                logger.warning("Consumption dimension %s is unavailable: %s", view, message)
        except CheckmarxPermissionError as exc:
            session.rollback()
            message = str(exc)
            _record_dimension(session, view, supported=None, error=message)
            dimension = DimensionResult(
                view_by=str(view), supported=False, error=message, read_failed=True
            )
            result.warnings.append(
                f"The API key is not permitted to read consumption by {view}. {message}"
            )
        except CheckmarxError as exc:
            # An outage, a rate limit or a truncated answer. Nothing was stored, so
            # the previous snapshot stays the latest one, and the other dimensions
            # are still read.
            session.rollback()
            message = str(exc)
            dimension = DimensionResult(
                view_by=str(view), supported=True, error=message, read_failed=True
            )
            result.errors.append(f"consumption by {view} could not be read: {message}")
            logger.warning("Consumption by %s could not be read this cycle: %s", view, message)

        result.dimensions[str(view)] = dimension
        # One short transaction per dimension.
        session.commit()

    return result


def _reprobe_due(state: DimensionState, *, now: datetime | None = None) -> bool:
    if state.last_checked_at is None:
        return True
    return (now or utcnow()) - state.last_checked_at >= REPROBE_UNSUPPORTED_AFTER


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


@dataclass
class _Fetched:
    """Everything one dimension returned, held in memory until it is judged."""

    raw_pages: list[dict]
    merged: dict[str, usage_api.ParsedUsageItem]
    total_items: int | None
    pages: int
    # Rows read across every page, before rows for the same subject (the same
    # email or name, reported more than once) were merged.
    rows: int = 0

    @property
    def total_credits(self) -> Decimal:
        return sum((item.credits_used for item in self.merged.values()), Decimal("0"))


def _fetch_dimension(
    client: CheckmarxClient,
    *,
    view: UsageView,
    period_param: str,
    page_size: int,
    fallback_fingerprint: frozenset[str] | None = None,
) -> _Fetched:
    """Read every page for one dimension. Touches no database state.

    The whole answer is collected first so that a read which fails half way, or
    turns out to be truncated, leaves nothing behind: a partial or empty snapshot
    would become the "latest" one and be evaluated as though it were the truth.
    """
    raw_pages: list[dict] = []
    merged: dict[str, usage_api.ParsedUsageItem] = {}
    total_items: int | None = None
    total_pages: int | None = None
    pages = 0
    rows = 0
    last_page_size = 0

    for page in usage_api.fetch_usage(
        client, view_by=view, period=period_param, page_size=page_size
    ):
        pages += 1
        last_page_size = len(page.items)
        raw_items = page.raw.get("items") if isinstance(page.raw, dict) else None
        rows += len(raw_items) if isinstance(raw_items, list) else len(page.items)
        if page.raw is not None:
            raw_pages.append(page.raw)
        if page.total_items is not None:
            total_items = page.total_items
        if page.total_pages is not None:
            total_pages = page.total_pages
        for item in page.items:
            existing = merged.get(item.subject_key)
            if existing is None:
                merged[item.subject_key] = item
            else:
                # The same subject appearing on two pages would otherwise be
                # overwritten rather than combined.
                merged[item.subject_key] = _combine(existing, item)

    # The endpoint says how many pages there are. Stopping short of that (an empty
    # page in the middle, or the safety cap on page count) means consumption is
    # missing, and under-counted usage must not be stored as the whole picture.
    if total_pages is not None and pages < total_pages:
        raise UsageIncompleteError(
            f"Only {pages} of {total_pages} pages of consumption by {view} could be read."
        )
    if total_pages is None and pages >= usage_api.MAX_PAGES and last_page_size >= page_size:
        raise UsageIncompleteError(
            f"Consumption by {view} did not end within {usage_api.MAX_PAGES} pages."
        )

    # Compare against the deliberate bad-parameter probe before storing anything. An
    # identical subject set means this dimension does not exist and we were handed the
    # user view, which would otherwise be filed as project or application usage.
    # Both sides must be non empty: two empty responses are identical without
    # telling us anything, and a real but idle dimension legitimately returns none.
    if fallback_fingerprint and merged and frozenset(merged.keys()) == fallback_fingerprint:
        raise FallbackDetected(
            f"viewBy={view} returned the same subjects as an unrecognised viewBy "
            "value, so the endpoint silently fell back to the user dimension."
        )

    return _Fetched(
        raw_pages=raw_pages, merged=merged, total_items=total_items, pages=pages, rows=rows
    )


def _hold_reason(
    session: Session, *, view: UsageView, period_param: str, total: Decimal
) -> str | None:
    """Why this read should not be believed yet, or None if it should.

    Judged against the last read that *was* believed for the same lookback
    window. A change of window legitimately changes every total, so a snapshot
    taken with a different window is no yardstick.
    """
    previous = session.scalar(
        select(UsageSnapshot)
        .where(
            UsageSnapshot.view_by == str(view),
            UsageSnapshot.period_param == period_param,
            UsageSnapshot.held_reason.is_(None),
        )
        .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
        .limit(1)
    )
    if previous is None or previous.total_credits <= 0:
        return None
    if total >= previous.total_credits * HOLD_DROP_RATIO:
        return None

    # The run of held reads immediately before this one (everything since the
    # last believed read is held, by construction).
    held_run = list(
        session.scalars(
            select(UsageSnapshot)
            .where(
                UsageSnapshot.view_by == str(view),
                UsageSnapshot.period_param == period_param,
                UsageSnapshot.id > previous.id,
                UsageSnapshot.held_reason.is_not(None),
            )
            .order_by(UsageSnapshot.id)
        )
    )
    now = utcnow()
    # "The same story": no held read is wildly different from this one. A feed
    # that returns nothing, then a third, then nothing is still misbehaving.
    consistent = all(_similar(row.total_credits, total) for row in held_run)
    long_enough = bool(held_run) and now - held_run[0].collected_at >= HOLD_MIN_DURATION
    if len(held_run) + 1 >= HOLD_CONFIRMATIONS and long_enough and consistent:
        logger.warning(
            "Consumption by %s fell from %s to %s and has stayed there for %d reads over "
            "%s, so it is accepted",
            view,
            previous.total_credits,
            total,
            len(held_run) + 1,
            now - held_run[0].collected_at,
        )
        return None
    return (
        f"Checkmarx reported {total} credits by {view}, down from {previous.total_credits} "
        f"on the last accepted read. A collapse like that is usually a faulty answer "
        f"rather than real usage, so it is being held back and limits are still judged "
        f"on the previous figures. It is accepted once it has persisted for at least "
        f"{HOLD_CONFIRMATIONS} reads over {int(HOLD_MIN_DURATION.total_seconds() // 3600)} "
        f"hours ({len(held_run) + 1} so far)."
    )


def _similar(first: Decimal, second: Decimal) -> bool:
    """Two held totals tell the same story: both nothing, or within 2x of each other."""
    low, high = sorted((first, second))
    if high <= 0:
        return True
    return low * 2 >= high


def _store_dimension(
    session: Session,
    fetched: _Fetched,
    *,
    view: UsageView,
    period_param: str,
    user_index: UserIndex,
    projects_by_id: dict[str, str],
    projects_by_name: dict[str, str],
    apps_by_id: dict[str, str],
    apps_by_name: dict[str, str],
    groups_by_id: dict[str, str] | None = None,
    groups_by_name: dict[str, str] | None = None,
) -> DimensionResult:
    """Write one fully fetched dimension. Makes no network calls."""
    now = utcnow()
    merged = fetched.merged
    held_reason = _hold_reason(
        session, view=view, period_param=period_param, total=fetched.total_credits
    )
    snapshot = UsageSnapshot(
        collected_at=now,
        view_by=str(view),
        period_param=period_param,
        total_items=fetched.total_items,
        pages_fetched=fetched.pages,
        total_credits=fetched.total_credits,
        held_reason=held_reason,
    )
    if held_reason is not None:
        # A held read carries no records: its response pages are the only
        # evidence of what was returned. A believed read's pages are not kept
        # (nothing reads them; every row is in its records, with its own raw
        # row for a week, see retention.py).
        snapshot.raw = fetched.raw_pages
    session.add(snapshot)
    session.flush()

    if held_reason is not None:
        # Kept as evidence of what was returned, but with no records and no
        # effect on attribution: nothing downstream may treat it as usage.
        return DimensionResult(
            view_by=str(view),
            supported=True,
            snapshot_id=snapshot.id,
            total_credits=fetched.total_credits,
            error=held_reason,
            held=True,
        )

    # The feed lists one subject more than once (on a live tenant, 119 user rows
    # for 87 people: the same person under their email and their name), and
    # those rows are merged. That is expected; only fewer rows than the feed
    # says it has is a shortfall worth a warning.
    if fetched.total_items is not None and fetched.rows < fetched.total_items:
        logger.warning(
            "Consumption by %s returned %d rows but reports %d items",
            view,
            fetched.rows,
            fetched.total_items,
        )
    elif fetched.rows > len(merged):
        logger.info(
            "Consumption by %s: %d rows merged into %d subjects reported more than once",
            view,
            fetched.rows,
            len(merged),
        )

    result = DimensionResult(view_by=str(view), supported=True, snapshot_id=snapshot.id)
    total = Decimal("0")

    # Mappings and the readings they re-point are changed under this lock, so
    # they are read here, after taking it, not from the indexes built before
    # the network reads: a mapping made while this cycle was reading counts
    # from its own anchor, never from a stale index.
    attribution_lock(session)
    if view == UsageView.USER:
        user_index = replace(user_index, pinned=_pinned_users(session))
    elif view in (UsageView.PROJECT, UsageView.APPLICATION):
        model = CxProject if view == UsageView.PROJECT else CxApplication
        fresh = entity_mappings(session).get(str(view))
        by_id, by_name = _named_index(session, model, fresh)
        if view == UsageView.PROJECT:
            projects_by_id, projects_by_name = by_id, by_name
        else:
            apps_by_id, apps_by_name = by_id, by_name
    anchors = _Anchors(session, view, snapshot)

    for item in merged.values():
        outcome: MatchOutcome | None = None
        key = item.subject_key[:320]
        if view == UsageView.USER:
            outcome = user_index.resolve_detailed(
                subject_key=item.subject_key,
                name=item.subject_name,
                email=item.subject_email,
                integrations=True,
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
        # A disputed subject is left uncounted on purpose: never kept on the
        # user it last counted towards.
        may_keep = outcome is None or outcome.method != MatchMethod.DISPUTED
        placed = anchors.attribute(
            key, entity_id, item.credits_used, item.actions or None, may_keep=may_keep
        )
        if placed.entity_id is not None and entity_id is None:
            entity_type = _VIEW_ENTITY.get(str(view), entity_type)
        entity_id = placed.entity_id
        if view != UsageView.USER and entity_type is not None and entity_id is None:
            # Reported under a name (or id) that is no synced entity: it
            # counts towards no limit. Counted, so it is never silent.
            result.unmatched_entities += 1
            result.unmatched_credits += item.credits_used
        session.add(
            UsageRecord(
                snapshot_id=snapshot.id,
                view_by=str(view),
                subject_key=key,
                subject_name=item.subject_name,
                subject_email=item.subject_email,
                entity_type=entity_type,
                entity_id=entity_id,
                credits_used=item.credits_used,
                attributed_credits=placed.attributed,
                held_reason=placed.held_reason,
                held_readings=placed.held_readings,
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
                result.automated_credits += item.credits_used
            else:
                _apply_user_outcome(session, item, outcome, now, result)

    # Names the last reading counted towards an entity but this one does not
    # report at all: carried for a few readings (see _Anchors.carry).
    for carried in anchors.carry({merged_key[:320] for merged_key in merged}):
        session.add(carried)

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
    elif outcome.is_bot:
        # Automation (a bot, an integration identity): visible, never a person.
        result.automated += 1
        result.automated_credits += item.credits_used
    else:
        # A plain miss still counts towards the unmatched banner.
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
        # The consumption feed owns a row it shares a key with: a row first
        # raised as a scan initiator becomes a consumption subject.
        row.view_by = UsageView.USER
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
                f"{top.label} at {round(top.score * 100)}% confidence. Override it under "
                "Settings → Attribution if this is wrong."
            ),
        )


# ------------------------------------------------------- forward-only attribution
#
# The consumption feed reports cumulative totals over its lookback window. A
# name that starts to count towards an entity part way (an admin maps it, a
# project is renamed to it, or a sync brings the entity it names) would
# otherwise bring everything it ever reported into the entity's current budget
# period at once. Instead, the name is anchored at its reported total when it
# starts to count (``UsageAnchor.offset_credits``), and only what it reports
# beyond that counts (``UsageRecord.attributed_credits``). Period baselines are
# never shifted, so a mapping cannot race an evaluation.

# Mapping writes and the ingest's record writes both run under this lock, and
# neither holds it across a network call.
_ATTRIBUTION_LOCK_KEY = 0x43584147  # "CXAG"
ATTRIBUTION_LOCK_SETTING = "attribution.lock"


def attribution_lock(session: Session) -> None:
    """Serialise mapping writes against the ingest, until the transaction ends.

    PostgreSQL: a transaction-scoped advisory lock. SQLite: a write statement,
    which takes the database's single write lock at once (the driver opens the
    transaction at the first write); reads after it see every earlier commit.
    """
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ATTRIBUTION_LOCK_KEY})
        return
    from app.models.connection import AppSetting

    session.execute(
        update(AppSetting)
        .where(AppSetting.key == ATTRIBUTION_LOCK_SETTING)
        .values(value=AppSetting.value)
    )


def latest_live_snapshot(
    session: Session, view: UsageView | str, *, excluding: int | None = None
) -> UsageSnapshot | None:
    """The newest believed reading from the tenant (never a demo one)."""
    from app.services import settings_store

    query = select(UsageSnapshot).where(
        UsageSnapshot.view_by == str(view),
        UsageSnapshot.held_reason.is_(None),
        UsageSnapshot.period_param.is_distinct_from(settings_store.DEMO_PERIOD_PARAM),
    )
    if excluding is not None:
        query = query.where(UsageSnapshot.id != excluding)
    return session.scalar(
        query.order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc()).limit(1)
    )


_VIEW_ENTITY = {
    str(UsageView.USER): EntityType.USER,
    str(UsageView.PROJECT): EntityType.PROJECT,
    str(UsageView.APPLICATION): EntityType.APPLICATION,
    str(UsageView.GROUP): EntityType.GROUP,
}
_VIEW_MODEL = {
    str(UsageView.USER): CxUser,
    str(UsageView.PROJECT): CxProject,
    str(UsageView.APPLICATION): CxApplication,
    str(UsageView.GROUP): CxGroup,
}
_VIEW_KIND = {
    str(UsageView.USER): "user",
    str(UsageView.PROJECT): "project",
    str(UsageView.APPLICATION): "application",
    str(UsageView.GROUP): "group",
}
HOLD_READINGS_KEY = "attribution.hold_readings"
DEFAULT_HOLD_READINGS = 8

HELD_KEPT = "kept"
HELD_CARRIED = "carried"


def hold_readings(session: Session) -> int:
    """How many readings a name is kept on an entity that has just been
    deleted (unconfirmed), or carried while the feed does not report it."""
    from app.services import settings_store

    value = settings_store.get_value(session, HOLD_READINGS_KEY, DEFAULT_HOLD_READINGS)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return DEFAULT_HOLD_READINGS


@dataclass(frozen=True, slots=True)
class Placement:
    """Where one name's row counts, and how much of it."""

    entity_id: str | None
    attributed: Decimal | None = None
    held_reason: str | None = None
    held_readings: int | None = None


@dataclass(frozen=True, slots=True)
class _Before:
    entity_id: str | None
    credits: Decimal
    attributed: Decimal | None
    held_reason: str | None
    held_readings: int
    actions: dict | None
    record: UsageRecord | None = None


class _Anchors:
    """Where each name's usage counts, for one dimension's new reading.

    The rules, name by name (``attribute``):

    * A name counting through a live anchor (an admin's mapping, or a move)
      counts what it reported beyond the anchor's offset.
    * A name that did not count anywhere before (new, or unmatched until the
      sync brought its entity) counts in full: the first usage of a project
      or user created between two syncs is that entity's usage.
    * A name that counted towards one entity and now matches another moved:
      it is anchored at its previous total, so only what it reports from now
      on counts there.
    * A name that counted towards an entity and now matches nothing is kept
      there: for as long as that entity exists (a rename the sync learnt before
      the feed), or, once it was deleted, until a second complete sync confirms
      the deletion or ``hold_readings`` readings went by.

    Names missing from the reading altogether are carried (``carry``).
    """

    def __init__(self, session: Session, view: UsageView, snapshot: UsageSnapshot) -> None:
        self.session = session
        self.view = str(view)
        self.snapshot = snapshot
        self.now = utcnow()
        self.limit = hold_readings(session)
        self.anchors = {
            anchor.subject_key: anchor
            for anchor in session.scalars(
                select(UsageAnchor).where(UsageAnchor.view_by == self.view)
            )
        }
        self.previous = latest_live_snapshot(session, view, excluding=snapshot.id)
        self.before: dict[str, _Before] = {}
        if self.previous is not None:
            for record in session.scalars(
                select(UsageRecord).where(UsageRecord.snapshot_id == self.previous.id)
            ):
                self.before[record.subject_key] = _Before(
                    entity_id=record.entity_id,
                    credits=Decimal(record.credits_used or 0),
                    attributed=record.attributed_credits,
                    held_reason=record.held_reason,
                    held_readings=record.held_readings or 0,
                    actions=record.actions,
                    record=record,
                )
        self._states: dict[str, tuple[bool, datetime | None] | None] = {}
        # Entities a name started to count towards from nowhere in this reading.
        self.fresh: set[str] = set()

    # ---------------------------------------------------------------- helpers

    def _state(self, entity_id: str) -> tuple[bool, datetime | None] | None:
        """(deleted, deleted at) of a synced entity, None if it is not known."""
        if entity_id not in self._states:
            model = _VIEW_MODEL.get(self.view)
            row = (
                self.session.execute(
                    select(model.is_deleted, model.last_synced_at).where(model.id == entity_id)
                ).first()
                if model is not None
                else None
            )
            self._states[entity_id] = (bool(row[0]), row[1]) if row is not None else None
        return self._states[entity_id]

    def _gone(self, entity_id: str, held: int) -> bool:
        """True once a deleted entity's names may stop counting towards it."""
        from app.services import org_sync

        state = self._state(entity_id)
        if state is None:
            return True
        deleted, deleted_at = state
        if not deleted:
            return False
        if held >= self.limit:
            return True
        return org_sync.deletion_confirmed(self.session, _VIEW_KIND[self.view], deleted_at)

    def _through(self, anchor: UsageAnchor, credits: Decimal, actions: dict | None) -> Decimal:
        if credits < Decimal(anchor.offset_credits):
            # The lookback window rolled past usage from before the anchor:
            # re-anchor, so the name never counts less than nothing. What it
            # reported between the last reading and this one, if any, is not
            # counted (inherent: the feed gives no dates).
            anchor.offset_credits = credits
            anchor.reference_actions = actions
            anchor.snapshot_id = self.snapshot.id
            anchor.anchored_at = self.now
        return credits - Decimal(anchor.offset_credits)

    def _anchor(
        self,
        key: str,
        entity_id: str,
        offset: Decimal,
        actions: dict | None,
        *,
        removed_from: str | None,
    ) -> UsageAnchor:
        anchor = self.anchors.get(key)
        if anchor is None:
            anchor = UsageAnchor(view_by=self.view, subject_key=key)
            self.session.add(anchor)
            self.anchors[key] = anchor
        anchor.entity_id = entity_id
        anchor.offset_credits = offset
        anchor.reference_actions = actions
        anchor.snapshot_id = self.previous.id if self.previous is not None else None
        anchor.anchored_at = self.now
        anchor.reason = ANCHOR_MOVED
        anchor.released_at = None
        anchor.released_credits = None
        anchor.release_reason = None
        if removed_from is not None:
            anchor.removed_from = removed_from
            anchor.removed_at = self.now
        return anchor

    # ------------------------------------------------------------------ rules

    def attribute(
        self,
        key: str,
        entity_id: str | None,
        credits: Decimal,
        actions: dict | None,
        *,
        may_keep: bool = True,
    ) -> Placement:
        credits = Decimal(credits or 0)
        anchor = self.anchors.get(key)
        before = self.before.get(key)

        if entity_id is None:
            previous = before.entity_id if before is not None else None
            if previous is None or not may_keep:
                return Placement(None)
            held = before.held_readings + 1 if before.held_reason else 1
            if self._gone(previous, held - 1):
                if anchor is not None and anchor.released_at is None:
                    anchor.released_at = self.now
                    anchor.released_credits = credits
                    anchor.release_reason = RELEASE_DELETED
                return Placement(None)
            # Kept where it counted: a rename the sync learnt first, or an
            # entity just deleted (unconfirmed).
            attributed = None
            if anchor is not None and anchor.released_at is None and anchor.entity_id == previous:
                attributed = self._through(anchor, credits, actions)
            return Placement(previous, attributed, HELD_KEPT, held)

        if anchor is not None and anchor.entity_id == entity_id:
            if anchor.released_at is None:
                return Placement(entity_id, self._through(anchor, credits, actions))
            if anchor.release_reason == RELEASE_DELETED:
                # Its entity came back: the same anchor counts again, never a
                # new one.
                anchor.released_at = None
                anchor.released_credits = None
                anchor.release_reason = None
                return Placement(entity_id, self._through(anchor, credits, actions))

        if before is None or before.entity_id is None:
            # Counted nowhere before: a new entity's first usage counts in full.
            self.fresh.add(entity_id)
            return Placement(entity_id)
        if before.entity_id == entity_id:
            if before.attributed is None:
                return Placement(entity_id)
            # Counted from an offset whose anchor is gone: keep that offset.
            offset = max(Decimal("0"), min(before.credits - before.attributed, credits))
            self._anchor(key, entity_id, offset, before.actions, removed_from=None)
            return Placement(entity_id, credits - offset)
        # Moved from one entity to another: only what it reports from now on
        # counts at the new one, and the old one keeps what it counted within
        # its periods (see evaluation, baseline_names).
        offset = max(Decimal("0"), min(before.credits, credits))
        self._anchor(key, entity_id, offset, before.actions, removed_from=before.entity_id)
        return Placement(entity_id, credits - offset)

    def carry(self, reported: set[str]) -> list[UsageRecord]:
        """Rows for names the last reading counted and this one lacks.

        A one-off gap in the feed, or a rename the feed reported before the
        sync: the old name's row keeps counting for up to ``hold_readings``
        readings, so the entity's figure does not fall (and its period lose its
        usage) meanwhile. Not when a name started to count towards the same
        entity from nowhere in this reading (the renamed name took over), and
        not for an entity whose deletion is settled.
        """
        rows: list[UsageRecord] = []
        for key, before in self.before.items():
            if key in reported or before.entity_id is None or before.record is None:
                continue
            if before.entity_id in self.fresh:
                continue
            held = before.held_readings + 1 if before.held_reason == HELD_CARRIED else 1
            if held > self.limit:
                continue
            state = self._state(before.entity_id)
            if state is None or (state[0] and self._gone(before.entity_id, held - 1)):
                continue
            record = before.record
            rows.append(
                UsageRecord(
                    snapshot_id=self.snapshot.id,
                    view_by=record.view_by,
                    subject_key=record.subject_key,
                    subject_name=record.subject_name,
                    subject_email=record.subject_email,
                    entity_type=record.entity_type,
                    entity_id=record.entity_id,
                    credits_used=record.credits_used,
                    attributed_credits=record.attributed_credits,
                    held_reason=HELD_CARRIED,
                    held_readings=held,
                    transactions=record.transactions,
                    actions=record.actions,
                )
            )
        return rows


ANCHOR_MAPPING = "mapping"
ANCHOR_MOVED = "moved"
RELEASE_UNMAP = "unmap"
RELEASE_DELETED = "deleted"


@dataclass
class SubjectMove:
    """What re-pointing one reported name did to the latest reading."""

    name: str
    # What the name has reported in the latest reading.
    reported: Decimal = Decimal("0")
    # Where it counted before, and what of it counted there: no longer.
    previous_entity: str | None = None
    removed: Decimal = Decimal("0")
    # False: a real name match wins over the mapping, so nothing moved.
    followed: bool = True
    changed: bool = False


def move_subject(
    session: Session,
    *,
    view: UsageView | str,
    subject_key: str,
    entity_type: str,
    entity_id: str | None,
    follows,  # type: ignore[no-untyped-def]
) -> SubjectMove:
    """Point a reported name at ``entity_id`` (None: at nothing), forward only.

    Call under ``attribution_lock``. The latest live reading's row is re-pointed
    at once, and the name is anchored at what it has reported so far: only what
    it reports from now on counts towards the new entity. Unmapping takes away
    exactly what the name added since it was mapped. ``follows(record)`` says
    whether the row follows the mapping (a real name match wins).
    """
    view = str(view)
    snapshot = latest_live_snapshot(session, view)
    record = (
        session.scalar(
            select(UsageRecord).where(
                UsageRecord.snapshot_id == snapshot.id,
                UsageRecord.view_by == view,
                UsageRecord.subject_key == subject_key,
            )
        )
        if snapshot is not None
        else None
    )
    move = SubjectMove(name=(record.subject_name or record.subject_key) if record else subject_key)
    credits = Decimal(record.credits_used or 0) if record is not None else Decimal("0")
    move.reported = credits
    if record is not None:
        move.previous_entity = record.entity_id
        if not follows(record):
            move.followed = False
            return move
        if record.entity_id is not None and record.entity_id == entity_id:
            return move
        if record.entity_id is not None:
            move.removed = Decimal(
                record.attributed_credits
                if record.attributed_credits is not None
                else record.credits_used or 0
            )
    anchor = session.scalar(
        select(UsageAnchor).where(
            UsageAnchor.view_by == view, UsageAnchor.subject_key == subject_key
        )
    )
    now = utcnow()
    previous = record.entity_id if record is not None else None
    actions = record.actions if record is not None else None
    if anchor is None and (entity_id is not None or previous is not None):
        anchor = UsageAnchor(
            view_by=view,
            subject_key=subject_key,
            entity_id=entity_id or previous,
            offset_credits=credits,
            anchored_at=now,
            reason=ANCHOR_MAPPING,
        )
        session.add(anchor)
    if anchor is not None:
        if previous is not None:
            # Budgets that counted the name there keep what it counted before
            # their period began (evaluation, baseline_names).
            anchor.removed_from = previous
            anchor.removed_at = now
        if entity_id is None:
            if anchor.released_at is None:
                anchor.released_at = now
                anchor.released_credits = credits
            anchor.release_reason = RELEASE_UNMAP
        else:
            anchor.entity_id = entity_id
            anchor.offset_credits = credits
            anchor.reference_actions = actions
            anchor.snapshot_id = snapshot.id if snapshot is not None else None
            anchor.anchored_at = now
            anchor.reason = ANCHOR_MAPPING
            anchor.released_at = None
            anchor.released_credits = None
            anchor.release_reason = None
    if record is not None:
        record.entity_type = entity_type
        record.entity_id = entity_id
        record.attributed_credits = Decimal("0") if entity_id is not None else None
        record.held_reason = None
        record.held_readings = None
    move.changed = True
    session.flush()
    return move


# ------------------------------------------------------------------ reading back


def latest_snapshot(session: Session, view: UsageView | str) -> UsageSnapshot | None:
    from app.services import settings_store

    # A held snapshot is a read that was not believed, so it is never the latest.
    query = select(UsageSnapshot).where(
        UsageSnapshot.view_by == str(view), UsageSnapshot.held_reason.is_(None)
    )
    # Demo snapshots are only ever visible in demo mode. Outside it they are
    # hidden from every reader (dashboard and evaluation alike), so seeded demo
    # data can never be read as - or enforced as - live usage.
    if not settings_store.demo_mode(session):
        query = query.where(
            UsageSnapshot.period_param.is_distinct_from(settings_store.DEMO_PERIOD_PARAM)
        )
    return session.scalar(
        query.order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc()).limit(1)
    )


def latest_totals(session: Session, view: UsageView | str) -> dict[str, Decimal]:
    """Credit totals keyed by resolved entity id, from the newest snapshot.

    A name that started to count towards an entity after it had already
    reported usage (an admin's mapping, or a rename that made it match) adds
    only what it reported since: ``attributed_credits``.
    """
    snapshot = latest_snapshot(session, view)
    if snapshot is None:
        return {}
    rows = session.execute(
        select(
            UsageRecord.entity_id,
            func.sum(func.coalesce(UsageRecord.attributed_credits, UsageRecord.credits_used)),
        )
        .where(
            UsageRecord.snapshot_id == snapshot.id,
            UsageRecord.entity_id.is_not(None),
        )
        .group_by(UsageRecord.entity_id)
    ).all()
    return {entity_id: Decimal(str(total or 0)) for entity_id, total in rows if entity_id}


@dataclass(frozen=True, slots=True)
class NameRow:
    """One name of the newest reading, with what it counts and its anchor."""

    key: str
    entity_id: str | None
    counted: Decimal
    anchor_entity: str | None = None
    anchor_live: bool = False
    anchored_at: datetime | None = None
    removed_from: str | None = None
    removed_at: datetime | None = None


def latest_names(session: Session, view: UsageView | str) -> dict[str, NameRow]:
    """Every name of the newest reading, read in one statement with its anchor,
    so the figures and the anchors always describe the same moment (a mapping
    committed meanwhile is seen either entirely or not at all)."""
    snapshot = latest_snapshot(session, view)
    if snapshot is None:
        return {}
    rows = session.execute(
        select(
            UsageRecord.subject_key,
            UsageRecord.entity_id,
            func.coalesce(UsageRecord.attributed_credits, UsageRecord.credits_used),
            UsageAnchor.entity_id,
            UsageAnchor.released_at,
            UsageAnchor.anchored_at,
            UsageAnchor.removed_from,
            UsageAnchor.removed_at,
        )
        .select_from(UsageRecord)
        .outerjoin(
            UsageAnchor,
            (UsageAnchor.view_by == UsageRecord.view_by)
            & (UsageAnchor.subject_key == UsageRecord.subject_key),
        )
        .where(UsageRecord.snapshot_id == snapshot.id)
    ).all()
    return {
        key: NameRow(
            key=key,
            entity_id=entity_id,
            counted=Decimal(str(counted or 0)),
            anchor_entity=anchor_entity,
            anchor_live=anchor_entity is not None and released_at is None,
            anchored_at=anchored_at,
            removed_from=removed_from,
            removed_at=removed_at,
        )
        for (
            key,
            entity_id,
            counted,
            anchor_entity,
            released_at,
            anchored_at,
            removed_from,
            removed_at,
        ) in rows
    }


def anchors_for(session: Session, view: str, keys: list[str]) -> dict[str, UsageAnchor]:
    """The live anchors of these names (for ``forward_actions``)."""
    found: dict[str, UsageAnchor] = {}
    unique = sorted(set(keys))
    for start in range(0, len(unique), 500):
        for anchor in session.scalars(
            select(UsageAnchor).where(
                UsageAnchor.view_by == view,
                UsageAnchor.subject_key.in_(unique[start : start + 500]),
                UsageAnchor.released_at.is_(None),
            )
        ):
            found[anchor.subject_key] = anchor
    return found


def forward_actions(record: UsageRecord, anchors: dict[str, UsageAnchor]) -> dict:
    """A row's per action transactions that count towards its entity: for a
    name counting through an anchor, only those beyond the anchor's reference
    (the same rule as ``attributed_credits``)."""
    actions = record.actions or {}
    anchor = anchors.get(record.subject_key)
    if record.attributed_credits is None or anchor is None or anchor.entity_id != record.entity_id:
        return actions
    reference = anchor.reference_actions or {}
    forward: dict = {}
    for action, count in actions.items():
        before = reference.get(action, 0)
        if isinstance(count, int | float) and isinstance(before, int | float):
            forward[action] = max(0, count - before)
        else:
            forward[action] = count
    return forward


def totals_of(names: dict[str, NameRow]) -> dict[str, Decimal]:
    """``latest_totals`` from ``latest_names``."""
    totals: dict[str, Decimal] = {}
    for row in names.values():
        if row.entity_id:
            totals[row.entity_id] = totals.get(row.entity_id, Decimal("0")) + row.counted
    return totals


def dimension_supported(session: Session, view: UsageView | str) -> bool:
    """True unless a probe has positively established that the dimension is absent."""
    state = session.get(DimensionState, str(view))
    return True if state is None else state.supported is not False
