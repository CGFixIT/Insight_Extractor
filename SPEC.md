# SPEC.md — insight_extractor

## Overview
Refactored BERT + regex insight extractor as a modern Python 3.12+ package with Pydantic models, proper sentence tokenization, and comprehensive tests.

## Python Version
Python 3.12+

## Project Structure
```
insight_extractor/
├── pyproject.toml
├── requirements.txt
├── constraints.txt
├── README.md
├── src/
│   └── insight_extractor/
│       ├── __init__.py
│       ├── __main__.py
│       ├── models.py        # Pydantic models
│       ├── config.py        # StrEnum definitions
│       ├── constants.py     # THREAD_SEEDS, REGEX_PATTERNS
│       ├── stemmer.py       # DynamicKeywordStemmer, KeywordPatternRegistry
│       ├── tokenizer.py     # SentenceTokenizer using model tokenizer
│       ├── extractor.py     # InsightExtractor (main class)
│       ├── exceptions.py    # Custom exceptions
│       └── utils.py         # Logging setup, helpers
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── unit/
    │   ├── __init__.py
    │   ├── test_stemmer.py
    │   ├── test_models.py
    │   ├── test_tokenizer.py
    │   └── test_exceptions.py
    └── integration/
        ├── __init__.py
        ├── test_extractor.py
        └── test_e2e.py
```

---

## Module: `config.py`

```python
from enum import StrEnum
from typing import final

@final
class StemMode(StrEnum):
    EXACT = "exact"
    STEM = "stem"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    FUZZY = "fuzzy"
    REGEX = "regex"

@final
class KeywordCategory(StrEnum):
    THREAT_INTEL = "threat_intel"
    OSINT = "osint"
    CHILD_SAFETY = "child_safety"
    AI_INFRA = "ai_infra"
    INFOSEC = "infosec"
    GENERAL = "general"

@final
class PatternLabel(StrEnum):
    CVE_ID = "CVE_ID"
    IP_ADDRESS = "IP_ADDRESS"
    HASH_SHA256 = "HASH_SHA256"
    HASH_MD5 = "HASH_MD5"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    BTC_WALLET = "BTC_WALLET"
    RANSOM_AMOUNT = "RANSOM_AMOUNT"
    FILE_EXTENSION = "FILE_EXTENSION"
    DARK_WEB = "DARK_WEB"
    TELEGRAM_HANDLE = "TELEGRAM_HANDLE"
    PORT_NUMBER = "PORT_NUMBER"
    TB_GB_DATA = "TB_GB_DATA"
    YEAR = "YEAR"
    PERCENTAGE = "PERCENTAGE"
    DYNAMIC_KEYWORD = "DYNAMIC_KEYWORD"
```

---

## Module: `models.py`

All models use Pydantic `BaseModel` v2 with `from __future__ import annotations`.

```python
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

class MatchInfo(BaseModel):
    match: str
    keyword: str
    start: int
    end: int
    stemmed: bool

class KeywordStats(BaseModel):
    total_keywords: int
    total_categories: int
    category_counts: dict[str, int]
    top_keywords: list[tuple[str, int]]
    stem_mode: str
    case_sensitive: bool
    custom_suffixes: tuple[str, ...]
    last_updated: str | None = None

class SemanticHit(BaseModel):
    keyword: str
    score: float
    context: str

class SentenceScore(BaseModel):
    sentence: str
    score: float

class ExtractResult(BaseModel):
    timestamp: str
    input_hash: str
    word_count: int
    regex_entities: dict[str, list[str]]
    dynamic_keyword_matches: dict[str, list[str]]
    semantic_keywords: list[SemanticHit]
    key_sentences: list[SentenceScore]
    newly_expanded_keywords: list[str]
    total_tracked_keywords: int
    keyword_stats: KeywordStats

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v
```

---

## Module: `exceptions.py`

```python
class InsightExtractorError(Exception):
    """Base exception for the insight_extractor package."""

class ConfigLoadError(InsightExtractorError):
    """Raised when configuration file loading fails."""

class ModelLoadError(InsightExtractorError):
    """Raised when the BERT model fails to load."""

class StateLoadError(InsightExtractorError):
    """Raised when state file loading fails."""

class PatternCompileError(InsightExtractorError):
    """Raised when regex pattern compilation fails."""
```

---

## Module: `constants.py`

Move `THREAD_SEEDS` and `REGEX_PATTERNS` here. Use type aliases from models.

```python
type RegexPatternDict = dict[str, str]
type KeywordList = list[str]

THREAD_SEEDS: KeywordList = [...same as original...]

REGEX_PATTERNS: RegexPatternDict = {
    PatternLabel.CVE_ID: r"CVE-\d{4}-\d{4,7}",
    ...
}
```

---

## Module: `tokenizer.py`

```python
from transformers import AutoTokenizer

class SentenceTokenizer:
    """Sentence tokenization using the model's HuggingFace tokenizer."""

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        self._tokenizer: AutoTokenizer | None = None

    @property
    def tokenizer(self) -> AutoTokenizer:
        if self._tokenizer is None:
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        return self._tokenizer

    def tokenize_sentences(self, text: str, max_tokens: int = 512) -> list[str]:
        """
        Split text into sentences using the tokenizer's capabilities.
        Falls back to regex sentence splitting if tokenizer lacks sentence-level support.
        Each sentence is guaranteed to be within max_tokens token budget.
        """
        # Try tokenizer's built-in sentence splitting
        # If not available, use regex: r"(?<=[.!?])\s+"
        # Then chunk sentences that exceed max_tokens using tokenizer.encode + sliding window

    def count_tokens(self, text: str) -> int:
        """Return token count for text."""
        return len(self.tokenizer.encode(text, add_special_tokens=False))

    def chunk_text(self, text: str, max_tokens: int = 512, overlap: int = 50) -> list[str]:
        """
        Split text into chunks of max_tokens with optional overlap.
        Uses the model's tokenizer for accurate token counting.
        """
        tokens = self.tokenizer.encode(text, add_special_tokens=False)
        chunks: list[str] = []
        start = 0
        while start < len(tokens):
            end = min(start + max_tokens, len(tokens))
            chunk_tokens = tokens[start:end]
            chunk_text = self.tokenizer.decode(chunk_tokens, skip_special_tokens=True)
            chunks.append(chunk_text)
            start += max_tokens - overlap
        return chunks
```

---

## Module: `stemmer.py`

Same as the current enhanced file's `DynamicKeywordStemmer` and `KeywordPatternRegistry` classes, but:
- Use Pydantic models where appropriate
- Import from `config.py`, `exceptions.py`, `constants.py`
- Type aliases: `MatchResultList = list[MatchInfo]` (Pydantic)

---

## Module: `extractor.py`

The main `InsightExtractor` class. Key changes:

```python
class InsightExtractor:
    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        config_path: str | Path | None = None,
        seed_keywords: list[str] | None = None,
        top_k: int = 10,
        similarity_threshold: float = 0.38,
        dynamic_expansion_top_n: int = 15,
        *,
        stem_mode: StemMode = StemMode.STEM,
        enable_dynamic_regex: bool = True,
        custom_stem_suffixes: tuple[str, ...] | None = None,
        output_dir: str | Path = ".",
    ) -> None:
        ...

    def extract(self, text: str, *, update_keywords: bool = True) -> ExtractResult:
        ...  # returns Pydantic ExtractResult

    def save_results_to_markdown(self, result: ExtractResult, filename: str = "insights_extracted.md") -> Path:
        """Write extraction results to a Markdown file in the output directory."""
        ...
```

The `save_results_to_markdown` method formats results as:
```markdown
# Insight Extraction Results

- **Timestamp**: {timestamp}
- **Input Hash**: {input_hash}
- **Word Count**: {word_count}
- **Total Tracked Keywords**: {total_tracked_keywords}

## Regex Entities

### CVE_ID
- match1
- match2

## Dynamic Keyword Matches
...

## Semantic Keywords
| Keyword | Score | Context |
|---------|-------|---------|
...

## Key Sentences
| Score | Sentence |
|-------|----------|
...

## Keyword Statistics
...
```

---

## Module: `utils.py`

```python
import logging
from pathlib import Path

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    ...

def truncate_text(text: str, max_length: int = 120) -> str:
    ...

def sanitize_filename(name: str) -> str:
    ...
```

---

## Module: `__main__.py`

```python
from insight_extractor.extractor import InsightExtractor
from insight_extractor.utils import setup_logging
from pathlib import Path
import sys

setup_logging()
extractor = InsightExtractor()
# ... same CLI logic as original, but call save_results_to_markdown() at end
```

---

## Module: `__init__.py`

```python
from __future__ import annotations

__version__ = "2.0.0"
__all__ = [
    "InsightExtractor",
    "DynamicKeywordStemmer",
    "KeywordPatternRegistry",
    "SentenceTokenizer",
    "StemMode",
    "KeywordCategory",
    "PatternLabel",
    "ExtractResult",
    "MatchInfo",
    "KeywordStats",
    "SemanticHit",
    "SentenceScore",
    "THREAD_SEEDS",
    "REGEX_PATTERNS",
    "InsightExtractorError",
    "ConfigLoadError",
    "ModelLoadError",
    "StateLoadError",
    "PatternCompileError",
]
```

---

## pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "insight-extractor"
version = "2.0.0"
description = "BERT + regex insight extractor with dynamic keyword stemmer"
readme = "README.md"
requires-python = ">=3.12"
license = {text = "MIT"}
authors = [{name = "Author", email = "author@example.com"}]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
]
dependencies = [
    "sentence-transformers>=3.0.0",
    "scikit-learn>=1.5.0",
    "pyyaml>=6.0",
    "pydantic>=2.0",
    "transformers>=4.40.0",
    "numpy>=1.26.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-asyncio>=0.23",
    "ruff>=0.6.0",
    "mypy>=1.11",
]

[project.scripts]
insight-extract = "insight_extractor.__main__:main"

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.mypy]
python_version = "3.12"
strict = true

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
addopts = "-v --tb=short"
```

---

## Test Requirements

### conftest.py
- Fixtures for `InsightExtractor`, `DynamicKeywordStemmer`, `SentenceTokenizer`
- Fixtures for sample texts, tmp directories

### test_stemmer.py
- Test all StemMode pattern generation
- Test stem variation generation
- Test compile_keywords with edge cases (empty, single, many)
- Test find_matches with positions
- Test add/remove keyword cache invalidation

### test_models.py
- Test all Pydantic model instantiation
- Test validation errors (bad timestamp, negative score, etc.)
- Test serialization/deserialization round-trip

### test_tokenizer.py
- Test sentence tokenization
- Test token counting
- Test text chunking with various sizes
- Test chunking with overlap

### test_extractor.py (integration)
- Test extract() returns ExtractResult
- Test regex entity extraction
- Test semantic keyword matching
- Test key sentence scoring
- Test keyword expansion
- Test state save/load round-trip
- Test markdown output generation

### test_e2e.py
- Full pipeline with sample text
- Verify all output fields present
- Verify markdown file written correctly
