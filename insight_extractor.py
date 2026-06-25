#!/usr/bin/env python3
"""
insight_extractor.py
--------------------
BERT + regex insight extractor with dynamic thread-aware keyword updating
and universal dynamically updated keyword stemmer regex system.

Modernized for Python 3.12+ with:
- PEP 695 type aliases, | union syntax, TypedDict
- StrEnum for pattern labels and stem modes
- match/case for config loading and pattern routing
- tomllib for TOML config support
- pathlib.Path throughout
- datetime.now(datetime.UTC) for timezone-aware datetimes
- TypedDict for structured return types
- functools.cached_property and lru_cache
- DynamicKeywordStemmer + KeywordPatternRegistry for stemmer-regex integration

Dependencies (already in PsyClaw requirements.txt or add):
    sentence-transformers
    scikit-learn
    pyyaml

Usage:
    extractor = InsightExtractor()
    results = extractor.extract(text)
    extractor.update_thread_keywords(new_text)  # call after each message
"""

from __future__ import annotations

__all__ = [
    "THREAD_SEEDS",
    "REGEX_PATTERNS",
    "StemMode",
    "KeywordCategory",
    "PatternLabel",
    "ExtractResult",
    "MatchInfo",
    "KeywordStats",
    "DynamicKeywordStemmer",
    "KeywordPatternRegistry",
    "InsightExtractor",
]


# ── Standard library imports ─────────────────────────────────────────────────
import ast as _ast
import json
import hashlib
import logging
import re
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from enum import StrEnum
from functools import cached_property, lru_cache
from pathlib import Path
from typing import (
    Any,
    TypedDict,
    final,
)

# ── Third-party imports ──────────────────────────────────────────────────────
import numpy as np
import yaml
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Try tomllib (Python 3.11+) for TOML config support
try:
    import tomllib  # type: ignore[import-untyped]
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("insight_extractor")


# ═══════════════════════════════════════════════════════════════════════════════
#  TYPE ALIASES  (PEP 695 — type statement)
# ═══════════════════════════════════════════════════════════════════════════════

type RegexPatternDict = dict[str, str]
type KeywordList = list[str]
type EntityResults = dict[str, list[str]]
type MatchResult = dict[str, str | int | bool]
type MatchResultList = list[MatchResult]
type SemanticHit = dict[str, str | float]
type SemanticHitList = list[SemanticHit]
type SentenceScore = dict[str, str | float]
type SentenceScoreList = list[SentenceScore]
type KeywordFreqPairs = list[tuple[str, int]]
type PatternDict = dict[str, re.Pattern[str]]
type TypedPatternDict = dict[str, re.Pattern[str]]


# ═══════════════════════════════════════════════════════════════════════════════
#  ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

@final
class StemMode(StrEnum):
    """Stemming mode for dynamic keyword pattern generation."""

    EXACT = "exact"       # r"\bkeyword\b"
    STEM = "stem"         # r"\bkeyword[sx-z]?\b" — simple suffix stem
    PREFIX = "prefix"     # r"\bkeyword\w*\b" — prefix match
    SUFFIX = "suffix"     # r"\b\w*keyword\b" — suffix match
    FUZZY = "fuzzy"       # r"\b\w*keyword\w*\b" — substring match
    REGEX = "regex"       # use keyword as raw regex (advanced)


@final
class KeywordCategory(StrEnum):
    """Semantic category for tracked keywords."""

    THREAT_INTEL = "threat_intel"
    OSINT = "osint"
    CHILD_SAFETY = "child_safety"
    AI_INFRA = "ai_infra"
    INFOSEC = "infosec"
    GENERAL = "general"


@final
class PatternLabel(StrEnum):
    """Built-in regex pattern labels for static entity extraction."""

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


# ═══════════════════════════════════════════════════════════════════════════════
#  TYPEDDICT RETURN TYPES
# ═══════════════════════════════════════════════════════════════════════════════

class MatchInfo(TypedDict):
    """Information about a single keyword match found in text."""

    match: str
    keyword: str
    start: int
    end: int
    stemmed: bool


class KeywordStats(TypedDict):
    """Statistics about the current keyword bank."""

    total_keywords: int
    total_categories: int
    category_counts: dict[str, int]
    top_keywords: KeywordFreqPairs
    stem_mode: str
    case_sensitive: bool
    custom_suffixes: tuple[str, ...]
    last_updated: str | None


class ExtractResult(TypedDict):
    """Structured result from the full extraction pipeline."""

    timestamp: str
    input_hash: str
    word_count: int
    regex_entities: EntityResults
    dynamic_keyword_matches: EntityResults
    semantic_keywords: SemanticHitList
    key_sentences: SentenceScoreList
    newly_expanded_keywords: KeywordList
    total_tracked_keywords: int
    keyword_stats: KeywordStats


# ═══════════════════════════════════════════════════════════════════════════════
#  STATIC DATA
# ═══════════════════════════════════════════════════════════════════════════════

# ── Thread-seeded keyword bank (populated from this session) ─────────────────
THREAD_SEEDS: KeywordList = [
    # Ransomware / threat intel
    "ransomware", "nitrogen", "foxconn", "ESXi", "conti", "ALPHV", "blackcat",
    "RaaS", "double extortion", "supply chain", "data breach", "exfiltration",
    "payload", "loader", "YARA", "veeam", "watchtowr", "CVE",
    # OSINT / identity
    "OSINT", "data broker", "NPD", "national public data", "SSN", "dox",
    "facial recognition", "biometric", "SIM swap", "credential reset",
    "identity theft", "breach data",
    # Child safety / predators
    "predator", "Roblox", "CSAM", "grooming", "blackmail", "coercion",
    "age verification", "Discord", "Telegram", "minor", "sextortion",
    # PsyClaw / AI infra
    "PsyClaw", "LangGraph", "ChromaDB", "BM25", "RRF", "RAG",
    "soul", "personality", "sanitizer", "telemetry", "offline",
    "BERT", "embedding", "semantic search", "hybrid retrieval",
    # InfoSec / general
    "zero-day", "exploit", "phishing", "malware", "APT", "threat actor",
    "lateral movement", "privilege escalation", "encryption", "decryption",
    "public key", "private key", "cryptographic",
]


# ── Regex pattern bank ────────────────────────────────────────────────────────
REGEX_PATTERNS: RegexPatternDict = {
    PatternLabel.CVE_ID:          r"CVE-\d{4}-\d{4,7}",
    PatternLabel.IP_ADDRESS:      r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    PatternLabel.HASH_SHA256:     r"\b[0-9a-fA-F]{64}\b",
    PatternLabel.HASH_MD5:        r"\b[0-9a-fA-F]{32}\b",
    PatternLabel.DOMAIN:          r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|edu|onion|xyz|co)\b",
    PatternLabel.EMAIL:           r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    PatternLabel.BTC_WALLET:      r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    PatternLabel.RANSOM_AMOUNT:   r"\$\s?\d[\d,]*(?:\.\d{2})?\s?(?:million|billion|M|B|k)?",
    PatternLabel.FILE_EXTENSION:  r"\.\b(?:exe|dll|ps1|bat|sh|py|bin|enc|locked)\b",
    PatternLabel.DARK_WEB:        r"\b\w+\.onion\b",
    PatternLabel.TELEGRAM_HANDLE: r"@[A-Za-z0-9_]{5,}",
    PatternLabel.PORT_NUMBER:     r"\bport\s+(\d{2,5})\b",
    PatternLabel.TB_GB_DATA:      r"\b\d+(?:\.\d+)?\s?(?:TB|GB|MB|terabyte|gigabyte)\b",
    PatternLabel.YEAR:            r"\b20[12]\d\b",
    PatternLabel.PERCENTAGE:      r"\b\d+(?:\.\d+)?%",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  DYNAMIC KEYWORD STEMMER
# ═══════════════════════════════════════════════════════════════════════════════

class DynamicKeywordStemmer:
    """
    Generates regex patterns from a keyword bank with configurable stemming.
    Patterns auto-update when keywords change.

    Parameters
    ----------
    stem_mode:
        Default stemming mode for pattern generation.
    case_sensitive:
        Whether matches are case-sensitive.
    custom_suffixes:
        Suffix tuple for STEM-mode expansion.
    max_pattern_length:
        Maximum length of a compiled regex pattern (safety limit).
    """

    def __init__(
        self,
        *,
        stem_mode: StemMode = StemMode.STEM,
        case_sensitive: bool = False,
        custom_suffixes: tuple[str, ...] = (
            "s", "es", "ed", "ing", "er", "est", "ly", "tion", "ness", "ment",
        ),
        max_pattern_length: int = 1000,
    ) -> None:
        self.stem_mode: StemMode = stem_mode
        self.case_sensitive: bool = case_sensitive
        self.custom_suffixes: tuple[str, ...] = custom_suffixes
        self.max_pattern_length: int = max_pattern_length

        # Internal caches — invalidated on keyword changes
        self._keywords: KeywordList = []
        self._compiled_master: re.Pattern[str] | None = None
        self._compiled_typed: TypedPatternDict | None = None
        self._last_updated: datetime | None = None

    # ── Representation ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"stem_mode={self.stem_mode!r}, "
            f"case_sensitive={self.case_sensitive}, "
            f"keywords={len(self._keywords)}, "
            f"suffixes={len(self.custom_suffixes)}"
            f")"
        )

    def __str__(self) -> str:
        flags = "case-sensitive" if self.case_sensitive else "case-insensitive"
        return (
            f"DynamicKeywordStemmer[{self.stem_mode.value}] "
            f"({len(self._keywords)} keywords, {flags})"
        )

    # ── Pattern generation ────────────────────────────────────────────────────

    def generate_pattern(self, keyword: str, mode: StemMode | None = None) -> str:
        """Generate a regex pattern for a single keyword."""
        effective_mode = mode or self.stem_mode
        escaped = re.escape(keyword)

        match effective_mode:
            case StemMode.EXACT:
                return rf"\b{escaped}\b"
            case StemMode.STEM:
                # Simple suffix stemming — keyword + optional common suffixes
                return rf"\b{escaped}(?:{'|'.join(re.escape(s) for s in self.custom_suffixes)})?\b"
            case StemMode.PREFIX:
                return rf"\b{escaped}\w*\b"
            case StemMode.SUFFIX:
                return rf"\b\w*{escaped}\b"
            case StemMode.FUZZY:
                return rf"\b\w*{escaped}\w*\b"
            case StemMode.REGEX:
                # Use keyword as raw regex — caller is responsible for validity
                return keyword
            case _:
                # Fallback for any unexpected mode value
                return rf"\b{escaped}\b"

    def generate_stem_variations(self, keyword: str) -> KeywordList:
        """
        Generate stemmed variations of a keyword for broader matching.

        Examples
        --------
        >>> stemmer = DynamicKeywordStemmer()
        >>> stemmer.generate_stem_variations("ransomware")
        ['ransomware', 'ransomwares']
        """
        variations = [keyword]
        keyword_lower = keyword.lower()

        # Strip trailing suffixes to find the root, then re-add all suffixes
        root = keyword_lower
        stripped = False
        for suffix in sorted(self.custom_suffixes, key=len, reverse=True):
            if root.endswith(suffix) and len(root) > len(suffix) + 2:
                root = root[: -len(suffix)]
                stripped = True
                break

        if stripped:
            variations.append(keyword_lower)
        else:
            # Add suffixed variations
            for suffix in self.custom_suffixes:
                candidate = keyword_lower + suffix
                if candidate not in variations:
                    variations.append(candidate)

        return variations

    # ── Compilation ───────────────────────────────────────────────────────────

    def compile_keywords(self, keywords: list[str]) -> re.Pattern[str]:
        """
        Compile all keywords into a single optimized regex pattern.

        Returns a compiled regex that matches any keyword variation.
        """
        if not keywords:
            return re.compile(r"(?!)")  # Never-match pattern

        patterns: list[str] = []
        for kw in keywords:
            pat = self.generate_pattern(kw)
            patterns.append(f"({pat})")

        combined = "|".join(patterns)

        # Safety guard: if combined pattern exceeds limit, truncate
        if len(combined) > self.max_pattern_length:
            log.warning(
                "Combined pattern exceeds max length (%d > %d); "
                "truncating to fit.",
                len(combined),
                self.max_pattern_length,
            )
            # Keep adding patterns until we hit the limit
            kept: list[str] = []
            total = 0
            for pat in patterns:
                if total + len(pat) + 1 <= self.max_pattern_length:
                    kept.append(pat)
                    total += len(pat) + 1
                else:
                    break
            combined = "|".join(kept)

        flags = 0 if self.case_sensitive else re.IGNORECASE
        return re.compile(combined, flags)

    def compile_typed_patterns(self, keywords: list[str]) -> TypedPatternDict:
        """
        Compile keywords into categorized patterns by type heuristic.

        Returns dict of pattern_type → compiled regex.
        Heuristic types: 'technical_terms', 'proper_nouns', 'general_terms'.
        """
        technical_terms: KeywordList = []
        proper_nouns: KeywordList = []
        general_terms: KeywordList = []

        for kw in keywords:
            kw_stripped = kw.strip()
            if not kw_stripped:
                continue

            # Heuristic: uppercase / mixed-case short tokens are likely proper nouns
            if (
                kw_stripped.isupper()
                and len(kw_stripped) <= 6
                and " " not in kw_stripped
            ):
                proper_nouns.append(kw_stripped)
            # Heuristic: contains digits, special chars, or is camelCase/PascalCase
            elif (
                any(c.isdigit() for c in kw_stripped)
                or "-" in kw_stripped
                or any(c.isupper() for c in kw_stripped[1:])
            ):
                technical_terms.append(kw_stripped)
            else:
                general_terms.append(kw_stripped)

        result: TypedPatternDict = {}
        if technical_terms:
            result["technical_terms"] = self.compile_keywords(technical_terms)
        if proper_nouns:
            result["proper_nouns"] = self.compile_keywords(proper_nouns)
        if general_terms:
            result["general_terms"] = self.compile_keywords(general_terms)

        return result

    # ── Keyword management ────────────────────────────────────────────────────

    def add_keyword(self, keyword: str) -> None:
        """Add a keyword and invalidate caches."""
        if keyword not in self._keywords:
            self._keywords.append(keyword)
            self._invalidate_caches()

    def remove_keyword(self, keyword: str) -> None:
        """Remove a keyword and invalidate caches."""
        if keyword in self._keywords:
            self._keywords.remove(keyword)
            self._invalidate_caches()

    def set_keywords(self, keywords: list[str]) -> None:
        """Replace the entire keyword bank and invalidate caches."""
        self._keywords = list(keywords)
        self._invalidate_caches()

    def _invalidate_caches(self) -> None:
        """Clear compiled pattern caches after keyword mutations."""
        self._compiled_master = None
        self._compiled_typed = None
        self._last_updated = datetime.now(timezone.utc)

    # ── Lazy compiled pattern ─────────────────────────────────────────────────

    @property
    def compiled_pattern(self) -> re.Pattern[str] | None:
        """Lazily compiled master pattern — rebuilt on cache miss."""
        if self._compiled_master is None and self._keywords:
            self._compiled_master = self.compile_keywords(self._keywords)
        return self._compiled_master

    # ── Matching ──────────────────────────────────────────────────────────────

    def find_matches(self, text: str) -> MatchResultList:
        """
        Find all keyword matches in text with position info.

        Returns list of dicts with keys:
            match:   the matched text substring
            keyword: the source keyword that produced this match
            start:   character start position
            end:     character end position
            stemmed: whether the match is a stemmed variation
        """
        if not self._keywords:
            return []

        pattern = self.compiled_pattern
        if pattern is None:
            return []

        results: MatchResultList = []
        seen: set[tuple[int, int]] = set()

        for match in pattern.finditer(text):
            span = match.span()
            if span in seen:
                continue
            seen.add(span)

            matched_text = match.group(0)
            # Determine which keyword produced the match
            source_keyword = self._resolve_source_keyword(matched_text)
            is_stemmed = source_keyword is not None and matched_text.lower() != source_keyword.lower()

            results.append({
                "match": matched_text,
                "keyword": source_keyword or matched_text,
                "start": span[0],
                "end": span[1],
                "stemmed": is_stemmed,
            })

        return results

    def _resolve_source_keyword(self, matched_text: str) -> str | None:
        """Map a matched text back to its originating keyword."""
        matched_lower = matched_text.lower()
        for kw in self._keywords:
            if matched_lower == kw.lower():
                return kw
        # Fuzzy fallback: check if match contains or is contained by a keyword
        for kw in self._keywords:
            kw_lower = kw.lower()
            if kw_lower in matched_lower or matched_lower in kw_lower:
                return kw
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  KEYWORD PATTERN REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class KeywordPatternRegistry:
    """
    Manages keyword-to-pattern mappings with auto-regeneration.
    Bridges static REGEX_PATTERNS with dynamic keyword stemmer patterns.
    """

    def __init__(
        self,
        *,
        static_patterns: dict[str, str] | None = None,
        stemmer: DynamicKeywordStemmer | None = None,
    ) -> None:
        self.static_patterns: RegexPatternDict = dict(static_patterns or {})
        self.stemmer: DynamicKeywordStemmer | None = stemmer
        self._dynamic_patterns: RegexPatternDict = {}
        self._compiled_dynamic: re.Pattern[str] | None = None

    # ── Representation ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"static={len(self.static_patterns)}, "
            f"dynamic={len(self._dynamic_patterns)}, "
            f"has_stemmer={self.stemmer is not None}"
            f")"
        )

    def __str__(self) -> str:
        return (
            f"KeywordPatternRegistry[{len(self.static_patterns)} static, "
            f"{len(self._dynamic_patterns)} dynamic]"
        )

    # ── Pattern merging ───────────────────────────────────────────────────────

    @property
    def all_patterns(self) -> RegexPatternDict:
        """
        Merge static + dynamic patterns.

        Dynamic patterns take precedence on key collision.
        """
        merged = dict(self.static_patterns)
        merged.update(self._dynamic_patterns)
        return merged

    # ── Dynamic pattern regeneration ──────────────────────────────────────────

    def regenerate_dynamic_patterns(self, keywords: list[str]) -> None:
        """Rebuild all dynamic patterns from current keyword list."""
        if self.stemmer is None:
            return

        self.stemmer.set_keywords(keywords)

        if keywords:
            # Build one master pattern that matches any keyword variation
            master_pattern = self.stemmer.compile_keywords(keywords).pattern
            self._dynamic_patterns = {
                PatternLabel.DYNAMIC_KEYWORD: master_pattern,
            }
            flags = 0 if self.stemmer.case_sensitive else re.IGNORECASE
            self._compiled_dynamic = re.compile(master_pattern, flags)
        else:
            self._dynamic_patterns = {}
            self._compiled_dynamic = None

    # ── Extraction ────────────────────────────────────────────────────────────

    def extract_all(self, text: str) -> EntityResults:
        """
        Run all patterns (static + dynamic) and return merged results.

        Static patterns are run individually per label.
        Dynamic matches are grouped under 'DYNAMIC_KEYWORD' key.
        """
        results: EntityResults = defaultdict(list)

        # Static patterns
        for label, pattern in self.static_patterns.items():
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
            except re.error as exc:
                log.warning("Invalid regex pattern '%s': %s", label, exc)
                continue

            if matches:
                seen: set[str] = set()
                for m in matches:
                    m_str = m if isinstance(m, str) else m[0]
                    if m_str not in seen:
                        results[label].append(m_str)
                        seen.add(m_str)

        # Dynamic keyword patterns
        if self._compiled_dynamic is not None:
            seen_dynamic: set[str] = set()
            for match in self._compiled_dynamic.finditer(text):
                m_str = match.group(0)
                if m_str not in seen_dynamic:
                    results[PatternLabel.DYNAMIC_KEYWORD].append(m_str)
                    seen_dynamic.add(m_str)

        return dict(results)


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════════

class ConfigLoadError(ValueError):
    """Raised when configuration file loading fails."""


class ModelLoadError(RuntimeError):
    """Raised when the BERT sentence-transformer model fails to load."""


class StateLoadError(ValueError):
    """Raised when state file loading fails."""


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class InsightExtractor:
    """
    Hybrid BERT + regex insight extractor with dynamic thread-aware
    keyword expansion and universal dynamically updated keyword stemmer
    regex system.

    Thread keywords update on each call to update_thread_keywords().
    Dynamic regex patterns are auto-regenerated when keywords change.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        config_path: str | None = None,
        seed_keywords: list[str] | None = None,
        top_k: int = 10,
        similarity_threshold: float = 0.38,
        dynamic_expansion_top_n: int = 15,
        *,
        stem_mode: StemMode = StemMode.STEM,
        enable_dynamic_regex: bool = True,
        custom_stem_suffixes: tuple[str, ...] | None = None,
    ) -> None:
        self.model_name: str = model_name
        self.top_k: int = top_k
        self.similarity_threshold: float = similarity_threshold
        self.dynamic_expansion_top_n: int = dynamic_expansion_top_n
        self.enable_dynamic_regex: bool = enable_dynamic_regex

        # Load config (TOML preferred, fall back to YAML)
        if config_path and not isinstance(config_path, Path):
            warnings.warn(
                "Passing a string config_path is deprecated; use pathlib.Path instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        self.config: dict[str, Any] = self._load_config(config_path) if config_path else {}

        # Keyword bank
        self.thread_keywords: KeywordList = list(
            seed_keywords if seed_keywords else THREAD_SEEDS
        )
        self._keyword_freq: Counter = Counter()
        self._tfidf_corpus: list[str] = []
        self._keyword_categories: dict[str, KeywordCategory] = {}

        # BERT model (lazy-loaded)
        self._model: SentenceTransformer | None = None
        self._keyword_embeddings: np.ndarray | None = None

        # Dynamic stemmer + pattern registry
        self.stemmer: DynamicKeywordStemmer = DynamicKeywordStemmer(
            stem_mode=stem_mode,
            case_sensitive=False,
            custom_suffixes=custom_stem_suffixes or (
                "s", "es", "ed", "ing", "er", "est", "ly", "tion", "ness", "ment",
            ),
        )
        self.stemmer.set_keywords(self.thread_keywords)

        self.pattern_registry: KeywordPatternRegistry = KeywordPatternRegistry(
            static_patterns=REGEX_PATTERNS,
            stemmer=self.stemmer,
        )

        # If dynamic regex is enabled, pre-build patterns from seed keywords
        if self.enable_dynamic_regex:
            self.pattern_registry.regenerate_dynamic_patterns(self.thread_keywords)

        # Categorize initial seed keywords heuristically
        self._auto_categorize_keywords()

        log.info(
            "InsightExtractor init | model=%s | seeds=%d | stem_mode=%s | dynamic_regex=%s",
            model_name,
            len(self.thread_keywords),
            stem_mode.value,
            enable_dynamic_regex,
        )

    # ── Representation ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"model_name={self.model_name!r}, "
            f"keywords={len(self.thread_keywords)}, "
            f"stem_mode={self.stemmer.stem_mode.value}, "
            f"dynamic_regex={self.enable_dynamic_regex}"
            f")"
        )

    def __str__(self) -> str:
        return (
            f"InsightExtractor[{self.model_name}] "
            f"({len(self.thread_keywords)} keywords, "
            f"stem={self.stemmer.stem_mode.value})"
        )

    # ── Config ────────────────────────────────────────────────────────────────

    @staticmethod
    def _load_config(path: str) -> dict[str, Any]:
        """
        Load configuration from TOML (preferred) or YAML file.

        Tries TOML first via tomllib (Python 3.11+), falls back to YAML.
        Raises ConfigLoadError on failure.
        """
        config_path = Path(path)
        if not config_path.exists():
            log.warning("Config file not found: %s", config_path)
            return {}

        try:
            match config_path.suffix.lower():
                case ".toml":
                    if tomllib is None:
                        raise ConfigLoadError(
                            f"TOML config '{path}' requires Python 3.11+ "
                            "with tomllib support."
                        )
                    with config_path.open("rb") as f:
                        return tomllib.load(f) or {}

                case ".yaml" | ".yml":
                    with config_path.open(encoding="utf-8") as f:
                        return yaml.safe_load(f) or {}

                case _:
                    # Unknown extension: try TOML first, then YAML
                    if tomllib is not None:
                        try:
                            with config_path.open("rb") as f:
                                return tomllib.load(f) or {}
                        except Exception:
                            pass
                    with config_path.open(encoding="utf-8") as f:
                        return yaml.safe_load(f) or {}

        except ConfigLoadError:
            raise
        except Exception as exc:
            raise ConfigLoadError(f"Failed to load config from '{path}': {exc}") from exc

    # ── BERT singleton ────────────────────────────────────────────────────────

    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load the SentenceTransformer model on first access."""
        if self._model is None:
            log.info("Loading BERT model: %s", self.model_name)
            try:
                self._model = SentenceTransformer(self.model_name)
            except Exception as exc:
                raise ModelLoadError(
                    f"Failed to load model '{self.model_name}': {exc}"
                ) from exc
            self._recompute_keyword_embeddings()
        return self._model

    def _recompute_keyword_embeddings(self) -> None:
        """Re-embed all current thread keywords."""
        if self._model and self.thread_keywords:
            self._keyword_embeddings = self._model.encode(
                self.thread_keywords,
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )

    # ── Keyword categorization ────────────────────────────────────────────────

    def _auto_categorize_keywords(self) -> None:
        """Heuristically categorize all current keywords."""
        threat_terms = {
            "ransomware", "nitrogen", "foxconn", "esxi", "conti", "alphv",
            "blackcat", "raas", "double extortion", "supply chain",
            "data breach", "exfiltration", "payload", "loader", "yara",
            "veeam", "watchtowr", "cve", "zero-day", "exploit", "phishing",
            "malware", "apt", "threat actor", "lateral movement",
            "privilege escalation", "encryption", "decryption",
            "public key", "private key", "cryptographic",
        }
        osint_terms = {
            "osint", "data broker", "npd", "national public data", "ssn",
            "dox", "facial recognition", "biometric", "sim swap",
            "credential reset", "identity theft", "breach data",
        }
        safety_terms = {
            "predator", "roblox", "csam", "grooming", "blackmail",
            "coercion", "age verification", "discord", "telegram",
            "minor", "sextortion",
        }
        ai_terms = {
            "psyclaw", "langgraph", "chromadb", "bm25", "rrf", "rag",
            "soul", "personality", "sanitizer", "telemetry", "offline",
            "bert", "embedding", "semantic search", "hybrid retrieval",
        }

        for kw in self.thread_keywords:
            kw_lower = kw.lower()
            if kw_lower in threat_terms or kw_lower in osint_terms or kw_lower in safety_terms or kw_lower in ai_terms:
                match kw_lower:
                    case _ if kw_lower in threat_terms:
                        self._keyword_categories[kw] = KeywordCategory.THREAT_INTEL
                    case _ if kw_lower in osint_terms:
                        self._keyword_categories[kw] = KeywordCategory.OSINT
                    case _ if kw_lower in safety_terms:
                        self._keyword_categories[kw] = KeywordCategory.CHILD_SAFETY
                    case _ if kw_lower in ai_terms:
                        self._keyword_categories[kw] = KeywordCategory.AI_INFRA
                    case _:
                        self._keyword_categories[kw] = KeywordCategory.GENERAL
            else:
                # Default heuristics
                if any(c.isupper() for c in kw[1:]):
                    self._keyword_categories[kw] = KeywordCategory.AI_INFRA
                elif kw.isupper() and len(kw) <= 6:
                    self._keyword_categories[kw] = KeywordCategory.INFOSEC
                else:
                    self._keyword_categories[kw] = KeywordCategory.GENERAL

    # ── Dynamic keyword expansion ─────────────────────────────────────────────

    def update_thread_keywords(
        self,
        new_text: str,
        *,
        auto_expand: bool = True,
    ) -> KeywordList:
        """
        Feed a new message/chunk into the keyword tracker.

        Adds high-TF-IDF terms from new_text that are semantically close
        to existing keywords (cosine >= similarity_threshold).

        Returns list of newly added keywords.
        """
        self._tfidf_corpus.append(new_text)
        new_keywords: KeywordList = []

        if not auto_expand or len(self._tfidf_corpus) < 2:
            return new_keywords

        try:
            tfidf = TfidfVectorizer(
                max_features=200,
                stop_words="english",
                ngram_range=(1, 3),
                min_df=1,
            )
            tfidf_matrix = tfidf.fit_transform(self._tfidf_corpus)
            feature_names = tfidf.get_feature_names_out()
            latest_scores = tfidf_matrix[-1].toarray().flatten()
            top_idx = np.argsort(latest_scores)[::-1][: self.dynamic_expansion_top_n]
            candidates = [feature_names[i] for i in top_idx if latest_scores[i] > 0]

            if not candidates:
                return new_keywords

            _ = self.model  # trigger lazy load
            cand_embs = self._model.encode(
                candidates,
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
            if self._keyword_embeddings is None:
                self._recompute_keyword_embeddings()

            sims = cosine_similarity(cand_embs, self._keyword_embeddings)
            max_sims = sims.max(axis=1)

            existing_lower = {k.lower() for k in self.thread_keywords}
            for i, cand in enumerate(candidates):
                if (
                    max_sims[i] >= self.similarity_threshold
                    and cand.lower() not in existing_lower
                    and len(cand) > 3
                ):
                    self.thread_keywords.append(cand)
                    new_keywords.append(cand)
                    self._keyword_freq[cand] = 0
                    self._keyword_categories[cand] = KeywordCategory.GENERAL
                    existing_lower.add(cand.lower())

            if new_keywords:
                log.info(
                    "Expanded keywords +%d: %s...",
                    len(new_keywords),
                    new_keywords[:5],
                )
                self._recompute_keyword_embeddings()

                # Auto-regenerate dynamic regex patterns
                if self.enable_dynamic_regex:
                    self.pattern_registry.regenerate_dynamic_patterns(
                        self.thread_keywords
                    )

        except (ValueError, RuntimeError) as exc:
            log.warning("Keyword expansion error: %s", exc)

        return new_keywords

    # ── Regex extraction (static — backward compatible) ───────────────────────

    def extract_regex_entities(self, text: str) -> EntityResults:
        """
        Run all static regex patterns; return dict of entity_type -> [matches].

        This method is preserved for backward compatibility.
        It uses the static REGEX_PATTERNS directly (not the registry).
        """
        results: EntityResults = defaultdict(list)
        for label, pattern in REGEX_PATTERNS.items():
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
            except re.error as exc:
                log.warning("Regex error in pattern '%s': %s", label, exc)
                continue

            if matches:
                seen: set[str] = set()
                for m in matches:
                    m_str = m if isinstance(m, str) else m[0]
                    if m_str not in seen:
                        results[label].append(m_str)
                        seen.add(m_str)
        return dict(results)

    # ── Dynamic entity extraction ─────────────────────────────────────────────

    def extract_dynamic_entities(self, text: str) -> EntityResults:
        """Extract using dynamically generated keyword stemmer patterns."""
        if not self.enable_dynamic_regex:
            return {}
        return self.pattern_registry.extract_all(text)

    # ── Keyword position extraction ───────────────────────────────────────────

    def extract_keywords_with_positions(self, text: str) -> list[dict[str, Any]]:
        """
        Returns all keyword matches with their character positions in the text.

        Each result dict contains: keyword, match, start, end, score, category.
        """
        if not self.thread_keywords:
            return []

        pattern = self.stemmer.compiled_pattern
        if pattern is None:
            return []

        results: list[dict[str, Any]] = []
        seen_spans: set[tuple[int, int]] = set()

        for match in pattern.finditer(text):
            span = match.span()
            if span in seen_spans:
                continue
            seen_spans.add(span)

            matched_text = match.group(0)
            source_keyword = self.stemmer._resolve_source_keyword(matched_text)

            category = (
                self._keyword_categories.get(source_keyword, KeywordCategory.GENERAL)
                if source_keyword
                else KeywordCategory.GENERAL
            )

            results.append({
                "keyword": source_keyword or matched_text,
                "match": matched_text,
                "start": span[0],
                "end": span[1],
                "category": category.value,
            })

        return results

    # ── BERT semantic keyword match ───────────────────────────────────────────

    def extract_semantic_keywords(
        self,
        text: str,
        *,
        chunk_size: int = 512,
    ) -> SemanticHitList:
        """
        Embed text chunks and find top-K keyword matches via cosine sim.

        Returns list of {keyword, score, context}.
        """
        _ = self.model  # trigger lazy load

        words = text.split()
        chunks = [
            " ".join(words[i : i + chunk_size])
            for i in range(0, max(len(words), 1), chunk_size)
        ]

        chunk_embs = self._model.encode(
            chunks,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )

        if self._keyword_embeddings is None:
            self._recompute_keyword_embeddings()

        sims = cosine_similarity(chunk_embs, self._keyword_embeddings)
        max_sims_per_kw = sims.max(axis=0)
        best_chunk_idx = sims.argmax(axis=0)

        hits: SemanticHitList = []
        for kw_idx, (kw, score) in enumerate(
            zip(self.thread_keywords, max_sims_per_kw)
        ):
            if score >= self.similarity_threshold:
                ctx = chunks[best_chunk_idx[kw_idx]][:120].replace("\n", " ")
                hits.append({
                    "keyword": kw,
                    "score": round(float(score), 4),
                    "context": ctx,
                })
                self._keyword_freq[kw] += 1

        hits.sort(key=lambda x: x["score"], reverse=True)  # type: ignore[arg-type]
        return hits[: self.top_k]

    # ── Sentence-level insight scoring ────────────────────────────────────────

    def extract_key_sentences(
        self,
        text: str,
        *,
        top_n: int = 5,
    ) -> SentenceScoreList:
        """
        Score each sentence by max cosine similarity to keyword bank.

        Returns top_n most insight-dense sentences.
        """
        _ = self.model
        sentences = [
            s.strip()
            for s in re.split(r"(?<=[.!?])\s+", text)
            if len(s.strip()) > 30
        ]
        if not sentences:
            return []

        sent_embs = self._model.encode(
            sentences,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        if self._keyword_embeddings is None:
            self._recompute_keyword_embeddings()

        sims = cosine_similarity(sent_embs, self._keyword_embeddings)
        scores = sims.max(axis=1)

        ranked = sorted(
            [
                {"sentence": s, "score": round(float(sc), 4)}
                for s, sc in zip(sentences, scores)
            ],
            key=lambda x: x["score"],  # type: ignore[arg-type]
            reverse=True,
        )
        return ranked[:top_n]

    # ── Keyword statistics ────────────────────────────────────────────────────

    def get_keyword_stats(self) -> KeywordStats:
        """
        Return statistics about the current keyword bank.

        Includes total count, category breakdowns, top keywords by frequency,
        and stemmer configuration.
        """
        category_counts: dict[str, int] = defaultdict(int)
        for cat in self._keyword_categories.values():
            category_counts[cat.value] += 1

        return {
            "total_keywords": len(self.thread_keywords),
            "total_categories": len(category_counts),
            "category_counts": dict(category_counts),
            "top_keywords": self._keyword_freq.most_common(20),
            "stem_mode": self.stemmer.stem_mode.value,
            "case_sensitive": self.stemmer.case_sensitive,
            "custom_suffixes": self.stemmer.custom_suffixes,
            "last_updated": (
                self.stemmer._last_updated.isoformat()
                if self.stemmer._last_updated
                else None
            ),
        }

    # ── Master extract ────────────────────────────────────────────────────────

    def extract(
        self,
        text: str,
        *,
        update_keywords: bool = True,
    ) -> ExtractResult:
        """
        Full extraction pipeline:
          1. Dynamic keyword expansion (optional)
          2. Static regex entity extraction
          3. Dynamic keyword entity extraction
          4. BERT semantic keyword matching
          5. BERT key sentence scoring

        Returns structured insight dict as ExtractResult.
        """
        if update_keywords:
            new_kw = self.update_thread_keywords(text)
        else:
            new_kw = []

        entities = self.extract_regex_entities(text)
        dynamic_entities = self.extract_dynamic_entities(text)
        semantic_kw = self.extract_semantic_keywords(text)
        key_sentences = self.extract_key_sentences(text)
        keyword_stats = self.get_keyword_stats()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input_hash": hashlib.sha256(text.encode()).hexdigest()[:16],
            "word_count": len(text.split()),
            "regex_entities": entities,
            "dynamic_keyword_matches": dynamic_entities,
            "semantic_keywords": semantic_kw,
            "key_sentences": key_sentences,
            "newly_expanded_keywords": new_kw,
            "total_tracked_keywords": len(self.thread_keywords),
            "keyword_stats": keyword_stats,
        }

    # ── State persistence ─────────────────────────────────────────────────────

    def save_state(self, path: str = "insight_extractor_state.json") -> None:
        """Persist keyword bank + freq data for thread continuity."""
        if not isinstance(path, Path):
            warnings.warn(
                "Passing a string path is deprecated; use pathlib.Path instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        state = {
            "thread_keywords": self.thread_keywords,
            "keyword_freq": dict(self._keyword_freq),
            "keyword_categories": {
                k: v.value for k, v in self._keyword_categories.items()
            },
            "corpus_length": len(self._tfidf_corpus),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        Path(path).write_text(
            json.dumps(state, indent=2),
            encoding="utf-8",
        )
        log.info("State saved → %s", path)

    def load_state(self, path: str = "insight_extractor_state.json") -> bool:
        """Restore keyword bank from previous session."""
        if not isinstance(path, Path):
            warnings.warn(
                "Passing a string path is deprecated; use pathlib.Path instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        state_path = Path(path)
        if not state_path.exists():
            return False
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.thread_keywords = state.get("thread_keywords", self.thread_keywords)
            self._keyword_freq = Counter(state.get("keyword_freq", {}))

            # Restore categories
            raw_cats = state.get("keyword_categories", {})
            self._keyword_categories = {
                k: KeywordCategory(v) if v in {c.value for c in KeywordCategory} else KeywordCategory.GENERAL
                for k, v in raw_cats.items()
            }

            self._keyword_embeddings = None  # force recompute on next use

            # Re-sync stemmer + registry
            self.stemmer.set_keywords(self.thread_keywords)
            if self.enable_dynamic_regex:
                self.pattern_registry.regenerate_dynamic_patterns(
                    self.thread_keywords
                )

            log.info(
                "State loaded ← %s (%d keywords)",
                path,
                len(self.thread_keywords),
            )
            return True
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            log.warning("State load failed: %s", exc)
            return False

    def top_keywords(self, n: int = 20) -> KeywordFreqPairs:
        """Returns most frequently matched keywords across all extractions."""
        return self._keyword_freq.most_common(n)


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI DEMO
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    extractor = InsightExtractor()
    extractor.load_state()

    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        text = """
        On May 11 2026, the Nitrogen ransomware group claimed to have stolen 8 terabytes
        of data from Foxconn North American facilities including Mount Pleasant Wisconsin.
        The group used leaked Conti 2 builder code targeting VMware ESXi environments.
        Coveware found a critical coding bug in the ESXi encryptor: files are encrypted
        with the wrong public key, making recovery impossible even after paying the ransom.
        Ryan Montgomery demonstrated live OSINT on Tucker Carlson, retrieving SSN and
        driver license number from the National Public Data breach of 2.9 billion records.
        He also showed how Roblox age-verified accounts can be purchased on eBay for
        a few dollars, bypassing facial biometric verification entirely.
        PsyClaw uses BERT embeddings with ChromaDB and BM25 hybrid retrieval via RRF fusion.
        CVE-2026-48710 affects the Starlette framework used in millions of AI agent pipelines.
        """

    results = extractor.extract(text)

    print("\n=== REGEX ENTITIES ===")
    for etype, vals in results["regex_entities"].items():
        print(f"  {etype}: {vals}")

    print("\n=== DYNAMIC KEYWORD MATCHES ===")
    for etype, vals in results["dynamic_keyword_matches"].items():
        print(f"  {etype}: {vals[:10]}{' ...' if len(vals) > 10 else ''}")

    print("\n=== SEMANTIC KEYWORD HITS (top 10) ===")
    for hit in results["semantic_keywords"]:
        print(f"  [{hit['score']:.3f}] {hit['keyword']}")
        print(f"           ...{hit['context'][:80]}...")

    print("\n=== KEY SENTENCES ===")
    for s in results["key_sentences"]:
        print(f"  [{s['score']:.3f}] {s['sentence'][:120]}")

    print(f"\n=== DYNAMIC EXPANSION: +{len(results['newly_expanded_keywords'])} new keywords ===")
    if results["newly_expanded_keywords"]:
        print(f"  {results['newly_expanded_keywords']}")

    print(f"\nTotal tracked keywords: {results['total_tracked_keywords']}")

    # Show keyword stats
    stats = results["keyword_stats"]
    print(f"\n=== KEYWORD STATS ===")
    print(f"  Categories: {stats['category_counts']}")

    extractor.save_state()
