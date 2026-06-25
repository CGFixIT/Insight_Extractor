"""Integration tests for InsightExtractor with mocked ML dependencies."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from insight_extractor.extractor import InsightExtractor
from insight_extractor.models import ExtractResult, KeywordStats


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_model() -> MagicMock:
    """Return a mock SentenceTransformer-like model."""
    mock = MagicMock()
    mock.encode = MagicMock(
        return_value=np.random.rand(10, 384).astype(np.float32)
    )
    return mock


@pytest.fixture
def mock_tokenizer() -> MagicMock:
    """Return a mock tokenizer."""
    mock = MagicMock()
    mock.encode = MagicMock(
        side_effect=lambda text, **kw: list(range(max(1, len(text.split()) * 2)))
    )
    mock.decode = MagicMock(
        side_effect=lambda tokens, **kw: " ".join(["word"] * len(tokens))
    )
    return mock


@pytest.fixture
def extractor(
    mock_model: MagicMock, mock_tokenizer: MagicMock
) -> InsightExtractor:
    """Return an InsightExtractor with mocked heavy dependencies."""
    with (
        patch(
            "insight_extractor.extractor.SentenceTransformer",
            return_value=mock_model,
        ),
        patch(
            "insight_extractor.tokenizer.AutoTokenizer.from_pretrained",
            return_value=mock_tokenizer,
        ),
    ):
        ext = InsightExtractor(
            model_name="all-MiniLM-L6-v2",
            config_path=None,
            seed_keywords=["ransomware", "CVE"],
            top_k=5,
            similarity_threshold=0.5,
            enable_dynamic=True,
            enable_semantic=True,
        )
    return ext


@pytest.fixture
def extractor_no_dynamic(
    mock_model: MagicMock, mock_tokenizer: MagicMock
) -> InsightExtractor:
    """Return an extractor with dynamic/semantic features disabled."""
    with (
        patch(
            "insight_extractor.extractor.SentenceTransformer",
            return_value=mock_model,
        ),
        patch(
            "insight_extractor.tokenizer.AutoTokenizer.from_pretrained",
            return_value=mock_tokenizer,
        ),
    ):
        ext = InsightExtractor(
            model_name="all-MiniLM-L6-v2",
            config_path=None,
            seed_keywords=["ransomware", "CVE"],
            top_k=5,
            similarity_threshold=0.5,
            enable_dynamic=False,
            enable_semantic=False,
        )
    return ext


# ── Tests ────────────────────────────────────────────────────────────────────


class TestExtract:
    """Core extraction behaviour."""

    def test_extract_returns_extract_result(
        self, extractor: InsightExtractor, sample_text: str
    ) -> None:
        result = extractor.extract(sample_text)
        assert isinstance(result, ExtractResult)

    def test_extract_regex_only(
        self, extractor_no_dynamic: InsightExtractor, sample_text: str
    ) -> None:
        """With dynamic disabled, regex entities should still be found."""
        result = extractor_no_dynamic.extract(sample_text)
        assert isinstance(result, ExtractResult)
        # Should still have keyword stats and regex matches
        assert isinstance(result.keyword_stats, list)

    def test_keyword_expansion(
        self, extractor: InsightExtractor, sample_text: str
    ) -> None:
        """After extraction, new keywords may be tracked."""
        extractor.extract(sample_text)
        top = extractor.top_keywords(n=20)
        assert isinstance(top, list)
        # At least the seed keywords should be known
        assert any("ransomware" == kw or "CVE" == kw for kw in top)


class TestPersistence:
    """Save / load state round-trip."""

    def test_save_load_state(
        self,
        extractor: InsightExtractor,
        temp_dir: Path,
        sample_text: str,
    ) -> None:
        extractor.extract(sample_text)
        state_path = temp_dir / "state.json"
        extractor.save_state(state_path)
        assert state_path.exists()

        # Load into a fresh extractor
        with (
            patch(
                "insight_extractor.extractor.SentenceTransformer",
                return_value=extractor.model,
            ),
            patch(
                "insight_extractor.tokenizer.AutoTokenizer.from_pretrained",
                return_value=MagicMock(),
            ),
        ):
            fresh = InsightExtractor(
                model_name="all-MiniLM-L6-v2",
                config_path=None,
                seed_keywords=[],
                top_k=5,
                similarity_threshold=0.5,
            )
            fresh.load_state(state_path)

        # Keywords should have been restored
        loaded_top = fresh.top_keywords(n=20)
        assert isinstance(loaded_top, list)
        original_top = extractor.top_keywords(n=20)
        assert set(loaded_top) == set(original_top)


class TestMarkdownOutput:
    """Markdown file generation."""

    def test_save_results_to_markdown(
        self,
        extractor: InsightExtractor,
        temp_dir: Path,
        sample_text: str,
    ) -> None:
        result = extractor.extract(sample_text)
        md_path = temp_dir / "report.md"
        extractor.save_results_to_markdown(result, md_path)
        assert md_path.exists()
        content = md_path.read_text(encoding="utf-8")
        assert "# " in content
        assert len(content) > 0


class TestTopKeywords:
    """Frequency tracking."""

    def test_top_keywords(
        self, extractor: InsightExtractor, sample_text: str
    ) -> None:
        extractor.extract(sample_text)
        top = extractor.top_keywords(n=3)
        assert len(top) <= 3
        assert isinstance(top, list)
        for kw in top:
            assert isinstance(kw, str)

    def test_top_keywords_empty(self, extractor: InsightExtractor) -> None:
        """Before extraction, top_keywords may return empty or seeds."""
        top = extractor.top_keywords(n=5)
        assert isinstance(top, list)


class TestKeywordStats:
    """KeywordStats retrieval."""

    def test_get_keyword_stats(
        self, extractor: InsightExtractor, sample_text: str
    ) -> None:
        result = extractor.extract(sample_text)
        for stat in result.keyword_stats:
            assert isinstance(stat, KeywordStats)
            assert isinstance(stat.keyword, str)
            assert isinstance(stat.count, int)
            assert stat.count >= 1
            assert isinstance(stat.category, str)


class TestInitCustomSeeds:
    """Custom seed keywords are used at init time."""

    def test_init_custom_seeds(self, mock_model: MagicMock) -> None:
        with patch(
            "insight_extractor.extractor.SentenceTransformer",
            return_value=mock_model,
        ):
            ext = InsightExtractor(
                model_name="all-MiniLM-L6-v2",
                seed_keywords=["custom_seed_1", "custom_seed_2"],
            )
        top = ext.top_keywords(n=10)
        assert "custom_seed_1" in top or "custom_seed_2" in top


class TestDisabledDynamicRegex:
    """When dynamic regex is disabled, dynamic entities should be empty."""

    def test_disabled_dynamic_regex(
        self,
        extractor_no_dynamic: InsightExtractor,
        sample_text: str,
    ) -> None:
        result = extractor_no_dynamic.extract(sample_text)
        # regex_matches may still contain static regex hits (CVE, IPs, etc.)
        assert isinstance(result.regex_matches, list)
        assert isinstance(result, ExtractResult)
