"""Tests for Pydantic v2 data models."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from insight_extractor.models import (
    ExtractResult,
    KeywordStats,
    MatchInfo,
    SemanticHit,
    SentenceScore,
)


class TestMatchInfo:
    """MatchInfo represents a regex/pattern match in text."""

    def test_match_info_valid(self) -> None:
        mi = MatchInfo(
            keyword="ransomware",
            span=(10, 20),
            matched_text="ransomware",
            category="threat_actor",
            stemmed=False,
        )
        assert mi.keyword == "ransomware"
        assert mi.span == (10, 20)
        assert mi.matched_text == "ransomware"
        assert mi.category == "threat_actor"
        assert mi.stemmed is False

    def test_match_info_invalid_types(self) -> None:
        """Passing wrong types should raise ValidationError."""
        with pytest.raises(ValidationError):
            MatchInfo(
                keyword=123,  # type: ignore[arg-type]
                span="not_a_tuple",  # type: ignore[arg-type]
                matched_text="text",
            )

    def test_match_info_defaults(self) -> None:
        """category defaults to empty string and stemmed to False."""
        mi = MatchInfo(keyword="CVE", span=(0, 3), matched_text="CVE")
        assert mi.category == ""
        assert mi.stemmed is False


class TestKeywordStats:
    """KeywordStats aggregates frequency and category information."""

    def test_keyword_stats_valid(self) -> None:
        ks = KeywordStats(
            keyword="ransomware",
            count=7,
            category="malware",
            sources=["regex", "semantic"],
        )
        assert ks.keyword == "ransomware"
        assert ks.count == 7
        assert ks.category == "malware"
        assert ks.sources == ["regex", "semantic"]

    def test_keyword_stats_defaults(self) -> None:
        ks = KeywordStats(keyword="CVE", count=2)
        assert ks.category == ""
        assert ks.sources == []


class TestSemanticHit:
    """SemanticHit represents a vector-similarity match."""

    def test_semantic_hit_valid(self) -> None:
        sh = SemanticHit(
            keyword="phishing",
            similarity=0.9234,
            matched_span=(5, 13),
            source_sentence="The phishing campaign targeted finance.",
        )
        assert sh.keyword == "phishing"
        assert sh.similarity == pytest.approx(0.9234)
        assert sh.matched_span == (5, 13)

    def test_semantic_hit_invalid_similarity(self) -> None:
        """Similarity must be a float in [0, 1] (if bounded) or at least a number."""
        with pytest.raises(ValidationError):
            SemanticHit(
                keyword="x",
                similarity="high",  # type: ignore[arg-type]
                matched_span=(0, 1),
                source_sentence="test",
            )


class TestSentenceScore:
    """SentenceScore ranks sentences by relevance."""

    def test_sentence_score_valid(self) -> None:
        ss = SentenceScore(
            sentence="The ransomware attack began at midnight.",
            score=0.87,
            keyword_hits=["ransomware", "attack"],
        )
        assert ss.sentence == "The ransomware attack began at midnight."
        assert ss.score == pytest.approx(0.87)
        assert ss.keyword_hits == ["ransomware", "attack"]


class TestExtractResult:
    """ExtractResult is the top-level output of the pipeline."""

    def test_extract_result_valid(self) -> None:
        """Construct with nested models."""
        er = ExtractResult(
            text_hash="a1b2c3",
            keywords=["ransomware", "CVE"],
            keyword_stats=[
                KeywordStats(keyword="ransomware", count=3, category="malware"),
                KeywordStats(keyword="CVE", count=1),
            ],
            regex_matches=[
                MatchInfo(
                    keyword="ransomware",
                    span=(4, 14),
                    matched_text="ransomware",
                    stemmed=True,
                ),
            ],
            semantic_matches=[
                SemanticHit(
                    keyword="exploit",
                    similarity=0.91,
                    matched_span=(20, 27),
                    source_sentence="The exploit was public.",
                ),
            ],
            sentence_scores=[
                SentenceScore(
                    sentence="The exploit was public.",
                    score=0.91,
                    keyword_hits=["exploit"],
                ),
            ],
            timestamp="2026-01-15T10:30:00+00:00",
        )
        assert er.text_hash == "a1b2c3"
        assert er.keywords == ["ransomware", "CVE"]
        assert len(er.keyword_stats) == 2
        assert len(er.regex_matches) == 1
        assert len(er.semantic_matches) == 1
        assert len(er.sentence_scores) == 1

    def test_extract_result_timestamp_validation(self) -> None:
        """A valid ISO-8601 string should be accepted."""
        er = ExtractResult(
            text_hash="abc",
            keywords=["k"],
            timestamp="2026-05-11T14:00:00Z",
        )
        assert er.timestamp == "2026-05-11T14:00:00Z"

    def test_extract_result_invalid_timestamp(self) -> None:
        """A malformed timestamp should fail Pydantic validation."""
        with pytest.raises(ValidationError):
            ExtractResult(
                text_hash="abc",
                keywords=["k"],
                timestamp="not-a-real-timestamp",
            )

    def test_extract_result_defaults(self) -> None:
        """Lists default to empty when omitted."""
        er = ExtractResult(text_hash="x", keywords=["y"])
        assert er.keyword_stats == []
        assert er.regex_matches == []
        assert er.semantic_matches == []
        assert er.sentence_scores == []


class TestModelSerialization:
    """Round-trip serialization of all models."""

    def test_model_serialization(self) -> None:
        mi = MatchInfo(keyword="CVE", span=(0, 3), matched_text="CVE-2025")
        d = mi.model_dump()
        assert isinstance(d, dict)
        assert d["keyword"] == "CVE"
        assert d["span"] == (0, 3)

    def test_model_json_roundtrip(self) -> None:
        original = KeywordStats(
            keyword="ransomware",
            count=5,
            category="malware",
            sources=["regex"],
        )
        json_str = original.model_dump_json()
        restored = KeywordStats.model_validate_json(json_str)
        assert restored.keyword == original.keyword
        assert restored.count == original.count
        assert restored.category == original.category
        assert restored.sources == original.sources

    def test_extract_result_json_roundtrip(self) -> None:
        original = ExtractResult(
            text_hash="deadbeef",
            keywords=["a", "b"],
            keyword_stats=[KeywordStats(keyword="a", count=1)],
            regex_matches=[
                MatchInfo(keyword="a", span=(0, 1), matched_text="a"),
            ],
            semantic_matches=[
                SemanticHit(
                    keyword="b",
                    similarity=0.85,
                    matched_span=(2, 3),
                    source_sentence="ab",
                ),
            ],
            sentence_scores=[
                SentenceScore(sentence="ab", score=0.5, keyword_hits=["a"]),
            ],
            timestamp="2026-06-01T00:00:00+00:00",
        )
        json_str = original.model_dump_json()
        restored = ExtractResult.model_validate_json(json_str)
        assert restored.text_hash == original.text_hash
        assert restored.keywords == original.keywords
        assert len(restored.keyword_stats) == 1
        assert len(restored.regex_matches) == 1
        assert len(restored.semantic_matches) == 1
        assert len(restored.sentence_scores) == 1
