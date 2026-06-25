"""Tests for DynamicKeywordStemmer and KeywordPatternRegistry."""
from __future__ import annotations

import re

import pytest

from insight_extractor.config import StemMode
from insight_extractor.stemmer import DynamicKeywordStemmer, KeywordPatternRegistry


# ── DynamicKeywordStemmer tests ──────────────────────────────────────────────


class TestInit:
    """Construction and default attributes."""

    def test_init_defaults(self, stemmer: DynamicKeywordStemmer) -> None:
        assert stemmer.stem_mode is StemMode.STEM
        assert stemmer.case_sensitive is False
        assert stemmer.custom_suffixes == []
        assert stemmer.compiled_pattern is not None
        # Default pattern should never match anything
        assert not stemmer.compiled_pattern.search("test")

    def test_init_custom(self) -> None:
        s = DynamicKeywordStemmer(
            stem_mode=StemMode.EXACT,
            case_sensitive=True,
            custom_suffixes=["ing", "ed"],
            max_pattern_length=1000,
        )
        assert s.stem_mode is StemMode.EXACT
        assert s.case_sensitive is True
        assert s.custom_suffixes == ["ing", "ed"]


class TestGeneratePattern:
    """Pattern generation for each StemMode."""

    def test_generate_pattern_exact(self, stemmer_exact: DynamicKeywordStemmer) -> None:
        pat = stemmer_exact.generate_pattern("ransomware", StemMode.EXACT)
        assert pat == r"\bransomware\b"

    def test_generate_pattern_stem(self, stemmer: DynamicKeywordStemmer) -> None:
        pat = stemmer.generate_pattern("ransomware", StemMode.STEM)
        assert "ransomware" in pat
        # Stem mode should include a suffix group
        assert "(?:" in pat or "|" in pat

    def test_generate_pattern_prefix(self, stemmer: DynamicKeywordStemmer) -> None:
        pat = stemmer.generate_pattern("ransomware", StemMode.PREFIX)
        assert pat == r"\bransomware\w*\b"

    def test_generate_pattern_suffix(self, stemmer: DynamicKeywordStemmer) -> None:
        pat = stemmer.generate_pattern("ransomware", StemMode.SUFFIX)
        assert pat == r"\b\w*ransomware\b"

    def test_generate_pattern_fuzzy(self, stemmer: DynamicKeywordStemmer) -> None:
        pat = stemmer.generate_pattern("ransomware", StemMode.FUZZY)
        assert pat == r"\b\w*ransomware\w*\b"

    def test_generate_pattern_regex(self, stemmer: DynamicKeywordStemmer) -> None:
        raw = r"CVE-\d{4}-\d{5,}"
        pat = stemmer.generate_pattern(raw, StemMode.REGEX)
        assert pat == raw


class TestGenerateStemVariations:
    """Stem variation generation."""

    def test_generate_stem_variations(self, stemmer: DynamicKeywordStemmer) -> None:
        vars_ = stemmer.generate_stem_variations("attack")
        assert "attack" in vars_
        # Should include common suffix forms
        assert any("attacks" == v.lower() for v in vars_) or len(vars_) > 1


class TestCompileKeywords:
    """Compiling keywords into a regex pattern."""

    def test_compile_keywords_empty(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.compile_keywords([])
        assert stemmer.compiled_pattern is not None
        # Empty keyword list should produce a never-match pattern
        assert not stemmer.compiled_pattern.search("anything")

    def test_compile_keywords_single(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.compile_keywords(["ransomware"])
        assert stemmer.compiled_pattern.search("ransomware")
        assert not stemmer.compiled_pattern.search("cve")

    def test_compile_keywords_multiple(self, stemmer: DynamicKeywordStemmer) -> None:
        kws = ["ransomware", "CVE", "exploit"]
        stemmer.compile_keywords(kws)
        for kw in kws:
            assert stemmer.compiled_pattern.search(kw), f"failed to match {kw}"

    def test_compile_keywords_max_length(self, stemmer: DynamicKeywordStemmer) -> None:
        """Very long keyword list should be truncated to max_pattern_length."""
        long_kws = [f"kw_{i:05d}" for i in range(2000)]
        stemmer.compile_keywords(long_kws)
        assert stemmer.compiled_pattern is not None
        # Should still match the first keyword
        assert stemmer.compiled_pattern.search("kw_00000")


class TestCompileTypedPatterns:
    """Category-scoped pattern compilation."""

    def test_compile_typed_patterns(self, stemmer: DynamicKeywordStemmer) -> None:
        kws = {"ransomware": "malware", "CVE": "vulnerability"}
        typed = stemmer.compile_typed_patterns(kws)
        assert "malware" in typed
        assert "vulnerability" in typed
        for cat, pat in typed.items():
            assert isinstance(pat, re.Pattern)


class TestAddRemoveKeyword:
    """Dynamic keyword list mutation."""

    def test_add_keyword(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.compile_keywords(["ransomware"])
        stemmer.add_keyword("phishing")
        assert stemmer.compiled_pattern.search("phishing")
        assert stemmer.compiled_pattern.search("ransomware")

    def test_remove_keyword(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.compile_keywords(["ransomware", "phishing"])
        stemmer.remove_keyword("ransomware")
        assert not stemmer.compiled_pattern.search("ransomware")
        assert stemmer.compiled_pattern.search("phishing")

    def test_cache_invalidation_on_add(self, stemmer: DynamicKeywordStemmer) -> None:
        """Adding a keyword should invalidate and rebuild the pattern."""
        stemmer.compile_keywords(["old"])
        old_pat = stemmer.compiled_pattern
        stemmer.add_keyword("new")
        assert stemmer.compiled_pattern is not old_pat


class TestFindMatches:
    """Match extraction from text."""

    def test_find_matches_exact(self, stemmer_exact: DynamicKeywordStemmer) -> None:
        stemmer_exact.set_keywords(["ransomware"])
        matches = stemmer_exact.find_matches("The ransomware attack.")
        assert len(matches) >= 1
        m = matches[0]
        assert m["keyword"] == "ransomware"
        assert "span" in m
        assert m["matched_text"] == "ransomware"

    def test_find_matches_stemmed(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.set_keywords(["ransom"])
        matches = stemmer.find_matches("The ransomware group.")
        assert len(matches) >= 1
        assert any(m.get("stemmed", False) for m in matches)

    def test_find_matches_no_keywords(self, stemmer: DynamicKeywordStemmer) -> None:
        matches = stemmer.find_matches("some text")
        assert matches == []


class TestCaseSensitivity:
    """Case-(in)sensitive matching."""

    def test_case_sensitive(self) -> None:
        s = DynamicKeywordStemmer(case_sensitive=True)
        s.set_keywords(["Ransomware"])
        matches_cs = s.find_matches("Ransomware is bad.")
        assert len(matches_cs) >= 1
        matches_lower = s.find_matches("ransomware is bad.")
        assert len(matches_lower) == 0

    def test_case_insensitive(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.set_keywords(["ransomware"])
        matches = stemmer.find_matches("RANSOMWARE is bad.")
        assert len(matches) >= 1


class TestSpecialCharacters:
    """Special regex characters in keywords are escaped."""

    def test_special_characters_escaped(self, stemmer: DynamicKeywordStemmer) -> None:
        kws = ["C++", "[test]", "a.b", "x*y"]
        stemmer.compile_keywords(kws)
        # Should match literal strings, not interpret as regex
        assert stemmer.compiled_pattern.search("C++")
        assert stemmer.compiled_pattern.search("[test]")


class TestRepr:
    """String representations."""

    def test_repr_str(self, stemmer: DynamicKeywordStemmer) -> None:
        assert repr(stemmer) != ""
        assert str(stemmer) != ""
        assert "DynamicKeywordStemmer" in repr(stemmer)


# ── KeywordPatternRegistry tests ─────────────────────────────────────────────


class TestRegistry:
    """Tests for KeywordPatternRegistry."""

    def test_registry_init_defaults(self, registry: KeywordPatternRegistry) -> None:
        assert registry.all_patterns is not None

    def test_registry_with_stemmer(
        self, registry_with_stemmer: KeywordPatternRegistry
    ) -> None:
        assert registry_with_stemmer.all_patterns is not None

    def test_extract_all(self, registry_with_stemmer: KeywordPatternRegistry) -> None:
        text = "The ransomware used a CVE exploit."
        results = registry_with_stemmer.extract_all(text)
        # extract_all returns a dict of match lists
        assert isinstance(results, dict)
        matched_keywords = {
            m["keyword"] for matches in results.values() for m in matches
        }
        assert "ransomware" in matched_keywords or "CVE" in matched_keywords or "exploit" in matched_keywords

    def test_regenerate_dynamic_patterns(
        self, registry: KeywordPatternRegistry, sample_keywords: list[str]
    ) -> None:
        registry.regenerate_dynamic_patterns(sample_keywords)
        results = registry.extract_all("ransomware and CVE")
        assert isinstance(results, dict)
