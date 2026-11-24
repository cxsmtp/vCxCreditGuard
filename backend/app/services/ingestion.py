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
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
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
    from app.services import settings_store

    mappings = settings_store.entity_mappings(session)
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

    for item in merged.values():
        outcome: MatchOutcome | None = None
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
            if entity_type is not None and entity_id is None:
                # Reported under a name (or id) that is no synced entity: it
                # counts towards no limit. Counted, so it is never silent.
                result.unmatched_entities += 1
                result.unmatched_credits += item.credits_used
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
                result.automated_credits += item.credits_used
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
