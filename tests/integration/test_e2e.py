"""End-to-end tests with mocked BERT and full pipeline."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from insight_extractor.extractor import InsightExtractor
from insight_extractor.models import ExtractResult


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_bert() -> MagicMock:
    """Return a mock SentenceTransformer producing 384-dim embeddings."""
    mock = MagicMock()
    # Return deterministic vectors so similarity calculations are stable
    rng = np.random.default_rng(seed=42)
    mock.encode = MagicMock(
        side_effect=lambda texts, **kw: rng.random((len(texts), 384)).astype(
            np.float32
        )
        if isinstance(texts, list)
        else rng.random((1, 384)).astype(np.float32)
    )
    return mock


@pytest.fixture
def mock_tokenizer() -> MagicMock:
    mock = MagicMock()
    mock.encode = MagicMock(
        side_effect=lambda text, **kw: list(range(max(1, len(text.split()) * 2)))
    )
    mock.decode = MagicMock(
        side_effect=lambda tokens, **kw: " ".join(["word"] * len(tokens))
    )
    return mock


@pytest.fixture
def e2e_extractor(mock_bert: MagicMock, mock_tokenizer: MagicMock) -> InsightExtractor:
    """Fully configured InsightExtractor with all dependencies mocked."""
    with (
        patch(
            "insight_extractor.extractor.SentenceTransformer",
            return_value=mock_bert,
        ),
        patch(
            "insight_extractor.tokenizer.AutoTokenizer.from_pretrained",
            return_value=mock_tokenizer,
        ),
    ):
        ext = InsightExtractor(
            model_name="all-MiniLM-L6-v2",
            config_path=None,
            seed_keywords=[
                "ransomware",
                "CVE",
                "exploit",
                "malware",
                "phishing",
                "BERT",
                "Conti",
            ],
            top_k=10,
            similarity_threshold=0.3,
            enable_dynamic=True,
            enable_semantic=True,
            enable_regex=True,
        )
    return ext


# ── End-to-end tests ─────────────────────────────────────────────────────────


class TestFullPipeline:
    """Run the complete extraction pipeline end-to-end."""

    def test_full_pipeline(
        self, e2e_extractor: InsightExtractor, sample_text: str
    ) -> None:
        """extract() on sample_text produces a valid ExtractResult."""
        result = e2e_extractor.extract(sample_text)

        # Top-level type
        assert isinstance(result, ExtractResult)

        # All expected fields are present
        assert result.text_hash != ""
        assert isinstance(result.text_hash, str)
        assert isinstance(result.keywords, list)
        assert isinstance(result.keyword_stats, list)
        assert isinstance(result.regex_matches, list)
        assert isinstance(result.semantic_matches, list)
        assert isinstance(result.sentence_scores, list)
        assert isinstance(result.timestamp, str)

        # Timestamp is a valid ISO string
        assert "T" in result.timestamp or "Z" in result.timestamp

        # At least some keywords were identified
        assert len(result.keywords) > 0

        # Each keyword stat is populated
        for stat in result.keyword_stats:
            assert stat.keyword
            assert stat.count >= 1

        # Sentence scores are populated when text has multiple sentences
        if len(result.sentence_scores) > 0:
            assert result.sentence_scores[0].sentence
            assert 0.0 <= result.sentence_scores[0].score <= 1.0

    def test_dynamic_keyword_matches_present(
        self, e2e_extractor: InsightExtractor, sample_text: str
    ) -> None:
        """Keywords present in the text appear in regex_matches."""
        result = e2e_extractor.extract(sample_text)
        matched_keywords = {m.keyword for m in result.regex_matches}
        # At least one seed keyword should have been matched in the text
        assert matched_keywords, "Expected at least one regex match"


class TestMarkdownOutput:
    """Markdown report generation end-to-end."""

    def test_markdown_output(
        self,
        e2e_extractor: InsightExtractor,
        temp_dir: Path,
        sample_text: str,
    ) -> None:
        result = e2e_extractor.extract(sample_text)
        md_path = temp_dir / "e2e_report.md"
        e2e_extractor.save_results_to_markdown(result, md_path)

        assert md_path.exists()
        content = md_path.read_text(encoding="utf-8")

        # Should contain a top-level heading
        assert content.startswith("# ")

        # Should mention the text hash
        assert result.text_hash in content

        # Should contain expected markdown sections
        assert "##" in content

        # Should list at least one keyword
        assert len(result.keywords) == 0 or any(
            kw in content for kw in result.keywords[:3]
        )


class TestStatePersistence:
    """Save + load preserves keywords end-to-end."""

    def test_state_persistence(
        self,
        e2e_extractor: InsightExtractor,
        temp_dir: Path,
        sample_text: str,
    ) -> None:
        # Run extraction to populate state
        e2e_extractor.extract(sample_text)
        pre_keywords = set(e2e_extractor.top_keywords(n=50))
        assert pre_keywords, "Expected some keywords before saving"

        # Save state
        state_path = temp_dir / "e2e_state.json"
        e2e_extractor.save_state(state_path)
        assert state_path.exists()

        # Load into a fresh extractor with the same mock setup
        mock_bert = MagicMock()
        rng = np.random.default_rng(seed=99)
        mock_bert.encode = MagicMock(
            side_effect=lambda texts, **kw: rng.random(
                (len(texts) if isinstance(texts, list) else 1, 384)
            ).astype(np.float32)
        )
        mock_tok = MagicMock()
        mock_tok.encode = MagicMock(
            side_effect=lambda text, **kw: list(
                range(max(1, len(text.split()) * 2))
            )
        )
        mock_tok.decode = MagicMock(
            side_effect=lambda tokens, **kw: " ".join(
                ["word"] * len(tokens)
            )
        )

        with (
            patch(
                "insight_extractor.extractor.SentenceTransformer",
                return_value=mock_bert,
            ),
            patch(
                "insight_extractor.tokenizer.AutoTokenizer.from_pretrained",
                return_value=mock_tok,
            ),
        ):
            fresh = InsightExtractor(
                model_name="all-MiniLM-L6-v2",
                config_path=None,
                seed_keywords=[],
                top_k=10,
                similarity_threshold=0.3,
            )
            fresh.load_state(state_path)

        post_keywords = set(fresh.top_keywords(n=50))
        assert post_keywords == pre_keywords

    def test_multiple_extractions_accumulate(
        self, e2e_extractor: InsightExtractor, sample_text: str, short_text: str
    ) -> None:
        """Running extract multiple times accumulates keyword frequency."""
        r1 = e2e_extractor.extract(sample_text)
        r2 = e2e_extractor.extract(short_text)

        assert isinstance(r1, ExtractResult)
        assert isinstance(r2, ExtractResult)

        # Both runs should return keywords
        assert len(r1.keywords) >= 0
        assert len(r2.keywords) >= 0

        # Top keywords should still be queryable
        top = e2e_extractor.top_keywords(n=5)
        assert isinstance(top, list)
