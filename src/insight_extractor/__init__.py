"""insight_extractor -- BERT + regex insight extractor with dynamic keyword stemmer."""
from __future__ import annotations

__version__ = "2.0.0"

from insight_extractor.config import KeywordCategory, PatternLabel, StemMode
from insight_extractor.constants import REGEX_PATTERNS, THREAD_SEEDS
from insight_extractor.exceptions import (
    ConfigLoadError,
    InsightExtractorError,
    ModelLoadError,
    PatternCompileError,
    StateLoadError,
)
from insight_extractor.models import (
    ExtractResult,
    KeywordStats,
    MatchInfo,
    SemanticHit,
    SentenceScore,
)

# Lazy imports for heavy ML dependencies
_IMPORT_MAP: dict[str, str] = {
    "DynamicKeywordStemmer": "insight_extractor.stemmer",
    "InsightExtractor": "insight_extractor.extractor",
    "KeywordPatternRegistry": "insight_extractor.stemmer",
    "SentenceTokenizer": "insight_extractor.tokenizer",
}


def __getattr__(name: str) -> object:
    if name in _IMPORT_MAP:
        import importlib
        module = importlib.import_module(_IMPORT_MAP[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ConfigLoadError",
    "DynamicKeywordStemmer",
    "ExtractResult",
    "InsightExtractor",
    "InsightExtractorError",
    "KeywordCategory",
    "KeywordPatternRegistry",
    "KeywordStats",
    "MatchInfo",
    "ModelLoadError",
    "PatternCompileError",
    "PatternLabel",
    "REGEX_PATTERNS",
    "SemanticHit",
    "SentenceScore",
    "SentenceTokenizer",
    "StateLoadError",
    "StemMode",
    "THREAD_SEEDS",
    "__version__",
]
