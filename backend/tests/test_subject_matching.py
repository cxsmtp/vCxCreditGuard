"""The pure fuzzy-matching policy: tokenising, scoring and classification."""

from __future__ import annotations

from app.services import subject_matching as sm
from app.services.subject_matching import MatchMethod, UserProfile


def profile(user_id: str, *identities: str) -> UserProfile:
    return UserProfile(user_id=user_id, label=user_id, tokens=sm.tokenize(*identities))


class TestTokenize:
    def test_a_cx_handle_reduces_to_its_name_tokens(self) -> None:
        assert sm.tokenize("cx-dave-dawson") == frozenset({"dave", "dawson"})

    def test_an_email_reduces_to_its_local_part(self) -> None:
        assert sm.tokenize("dave.dawson@example.com") == frozenset({"dave", "dawson"})

    def test_a_display_name_and_its_handle_and_email_all_agree(self) -> None:
        handle = sm.tokenize("cx-dave-dawson")
        name = sm.tokenize("Dave Dawson")
        email = sm.tokenize("dave.dawson@example.com")
        assert handle == name == email

    def test_single_character_noise_is_dropped(self) -> None:
        assert sm.tokenize("j-green") == frozenset({"green"})

    def test_multiple_identities_union_into_one_set(self) -> None:
        assert sm.tokenize("Carol", "carol.chen@x.com") == frozenset({"carol", "chen"})


class TestBotDetection:
    def test_a_bracketed_bot_is_flagged(self) -> None:
        assert sm.is_bot_subject("dependabot[bot]") is True

    def test_a_known_bot_name_is_flagged(self) -> None:
        assert sm.is_bot_subject("renovate") is True

    def test_a_real_person_is_not_a_bot(self) -> None:
        # "Abbot" contains "bot" but is a person, not automation.
        assert sm.is_bot_subject("Terry Abbot") is False


class TestSimilarity:
    def test_identical_token_sets_are_perfect(self) -> None:
        assert sm.similarity(frozenset({"dave", "dawson"}), frozenset({"dave", "dawson"})) == 1.0

    def test_a_typo_still_scores_high(self) -> None:
        score = sm.similarity(frozenset({"mathew", "ingram"}), frozenset({"matthew", "ingram"}))
        assert score >= sm.AUTO_MATCH_THRESHOLD

    def test_one_shared_name_is_a_dispute_not_an_auto_match(self) -> None:
        score = sm.similarity(frozenset({"dave"}), frozenset({"dave", "dawson"}))
        assert sm.DISPUTE_THRESHOLD <= score < sm.AUTO_MATCH_THRESHOLD

    def test_unrelated_names_score_low(self) -> None:
        assert sm.similarity(frozenset({"alice", "archer"}), frozenset({"bob", "baker"})) < 0.4

    def test_an_empty_side_is_zero(self) -> None:
        assert sm.similarity(frozenset(), frozenset({"a", "b"})) == 0.0


class TestClassify:
    profiles = (
        profile("u-dave", "Dave Dawson", "dave.dawson@example.com"),
        profile("u-matt", "Matthew Ingram", "matthew.ingram@example.com"),
        profile("u-seb", "Henry Hughes", "henry.hughes@example.com"),
    )

    def test_a_handle_auto_matches_its_owner(self) -> None:
        outcome = sm.classify(
            subject_key="cx-dave-dawson",
            name="cx-dave-dawson",
            email=None,
            profiles=self.profiles,
        )
        assert outcome.method == MatchMethod.FUZZY_AUTO
        assert outcome.user_id == "u-dave"
        assert outcome.counted_user_id == "u-dave"

    def test_a_typo_handle_auto_matches(self) -> None:
        outcome = sm.classify(
            subject_key="cx-mathew-ingram",
            name="cx-mathew-ingram",
            email=None,
            profiles=self.profiles,
        )
        assert outcome.method == MatchMethod.FUZZY_AUTO
        assert outcome.user_id == "u-matt"

    def test_a_first_name_only_is_disputed_with_suggestions(self) -> None:
        outcome = sm.classify(subject_key="dave", name="dave", email=None, profiles=self.profiles)
        assert outcome.method == MatchMethod.DISPUTED
        assert outcome.counted_user_id is None
        assert outcome.candidates and outcome.candidates[0].user_id == "u-dave"

    def test_two_people_with_the_same_name_are_disputed_not_guessed(self) -> None:
        # A perfect score against two different users must never silently pick one.
        twins = (
            profile("u-a", "Gus Green", "gus.green@a.com"),
            profile("u-b", "Gus Green", "gus.green@b.com"),
        )
        outcome = sm.classify(
            subject_key="cx-gus-green", name="cx-gus-green", email=None, profiles=twins
        )
        assert outcome.method == MatchMethod.DISPUTED
        assert {c.user_id for c in outcome.candidates} == {"u-a", "u-b"}

    def test_an_exact_name_wins_over_a_similar_one(self) -> None:
        # A clear best match past the ambiguity margin is applied automatically.
        outcome = sm.classify(
            subject_key="cx-henry-hughes",
            name="cx-henry-hughes",
            email=None,
            profiles=self.profiles,
        )
        assert outcome.method == MatchMethod.FUZZY_AUTO
        assert outcome.user_id == "u-seb"

    def test_an_unknown_person_is_unmatched(self) -> None:
        outcome = sm.classify(
            subject_key="departed.person@example.com",
            name=None,
            email="departed.person@example.com",
            profiles=self.profiles,
        )
        assert outcome.method == MatchMethod.UNMATCHED
        assert outcome.candidates == ()

    def test_a_bot_is_unmatched_and_flagged(self) -> None:
        outcome = sm.classify(
            subject_key="dependabot[bot]",
            name="dependabot[bot]",
            email=None,
            profiles=self.profiles,
        )
        assert outcome.method == MatchMethod.UNMATCHED
        assert outcome.is_bot is True
