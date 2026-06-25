"""pytest fixtures for insight_extractor."""

from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from insight_extractor.config import StemMode
from insight_extractor.stemmer import DynamicKeywordStemmer, KeywordPatternRegistry
from insight_extractor.tokenizer import SentenceTokenizer

# ── Sample data fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def sample_text() -> str:
    return """
    On May 11 2026, the Nitrogen ransomware group claimed to have stolen 8 terabytes
    of data from Foxconn North American facilities. CVE-2026-48710 affects the
    Starlette framework. The group used leaked Conti builder code targeting ESXi.
    PsyClaw uses BERT embeddings with ChromaDB and BM25 hybrid retrieval via RRF.
    """


@pytest.fixture
def short_text() -> str:
    return "The CVE-2025-12345 vulnerability was exploited by ransomware actors."


@pytest.fixture
def sample_keywords() -> list[str]:
    return ["ransomware", "CVE", "exploit", "malware", "phishing", "BERT"]


# ── Component fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def stemmer() -> DynamicKeywordStemmer:
    return DynamicKeywordStemmer()


@pytest.fixture
def stemmer_exact() -> DynamicKeywordStemmer:
    return DynamicKeywordStemmer(stem_mode=StemMode.EXACT)


@pytest.fixture
def registry() -> KeywordPatternRegistry:
    return KeywordPatternRegistry()


@pytest.fixture
def registry_with_stemmer(sample_keywords: list[str]) -> KeywordPatternRegistry:
    s = DynamicKeywordStemmer()
    s.set_keywords(sample_keywords)
    return KeywordPatternRegistry(stemmer=s)


@pytest.fixture
def tokenizer() -> SentenceTokenizer:
    # Use a tiny model to avoid downloading large files in tests
    return SentenceTokenizer()


# ── File system fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def temp_dir() -> Generator[Path]:
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def sample_state_file(temp_dir: Path, sample_keywords: list[str]) -> Path:
    state = {
        "thread_keywords": sample_keywords,
        "keyword_freq": {"ransomware": 5, "CVE": 3},
        "keyword_categories": dict.fromkeys(sample_keywords, "threat_intel"),
        "corpus_length": 2,
        "saved_at": "2026-01-01T00:00:00Z",
    }
    path = temp_dir / "test_state.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return path
