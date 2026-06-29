"""Tests for DynamicKeywordStemmer and KeywordPatternRegistry."""

from __future__ import annotations

import re

from insight_extractor.config import StemMode
from insight_extractor.stemmer import DynamicKeywordStemmer, KeywordPatternRegistry

# ── DynamicKeywordStemmer tests ──────────────────────────────────────────────


class TestInit:
    """Construction and default attributes."""

    def test_init_defaults(self, stemmer: DynamicKeywordStemmer) -> None:
        assert stemmer.stem_mode is StemMode.STEM
        assert stemmer.case_sensitive is False
        # Default suffixes tuple is non-empty
        assert isinstance(stemmer.custom_suffixes, tuple)
        assert len(stemmer.custom_suffixes) > 0
        # No keywords set yet — compiled_pattern is None
        assert stemmer.compiled_pattern is None

    def test_init_custom(self) -> None:
        s = DynamicKeywordStemmer(
            stem_mode=StemMode.EXACT,
            case_sensitive=True,
            custom_suffixes=("ing", "ed"),
            max_pattern_length=1000,
        )
        assert s.stem_mode is StemMode.EXACT
        assert s.case_sensitive is True
        assert s.custom_suffixes == ("ing", "ed")


class TestGeneratePattern:
    """Pattern generation for each StemMode."""

    def test_generate_pattern_exact(self, stemmer_exact: DynamicKeywordStemmer) -> None:
        pat = stemmer_exact.generate_pattern("ransomware", StemMode.EXACT)
        assert pat == r"\bransomware\b"

    def test_generate_pattern_stem(self, stemmer: DynamicKeywordStemmer) -> None:
        pat = stemmer.generate_pattern("ransomware", StemMode.STEM)
        assert "ransomware" in pat
        # Stem mode includes an optional suffix group
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
        assert len(vars_) > 1


class TestCompileKeywords:
    """Compiling keywords into a regex pattern via set_keywords."""

    def test_compile_keywords_empty(self, stemmer: DynamicKeywordStemmer) -> None:
        # No keywords — compiled_pattern is None
        assert stemmer.compiled_pattern is None

    def test_compile_keywords_single(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.set_keywords(["ransomware"])
        assert stemmer.compiled_pattern is not None
        assert stemmer.compiled_pattern.search("ransomware")
        assert not stemmer.compiled_pattern.search("cve")

    def test_compile_keywords_multiple(self, stemmer: DynamicKeywordStemmer) -> None:
        kws = ["ransomware", "CVE", "exploit"]
        stemmer.set_keywords(kws)
        assert stemmer.compiled_pattern is not None
        for kw in kws:
            assert stemmer.compiled_pattern.search(kw), f"failed to match {kw}"

    def test_compile_keywords_max_length_keeps_all_keywords(self) -> None:
        """Long keyword lists are chunked instead of truncated."""
        stemmer = DynamicKeywordStemmer(stem_mode=StemMode.EXACT, max_pattern_length=50)
        long_kws = [f"kw_{i:05d}" for i in range(200)]
        stemmer.set_keywords(long_kws)
        assert stemmer.compiled_pattern is not None
        text = " ".join(long_kws)
        matches = {match.match for match in stemmer.find_matches(text)}
        assert matches == set(long_kws)


class TestCompileTypedPatterns:
    """Category-scoped pattern compilation."""

    def test_compile_typed_patterns(self, stemmer: DynamicKeywordStemmer) -> None:
        kws = ["ransomware", "CVE", "exploit"]
        typed = stemmer.compile_typed_patterns(kws)
        # Method returns a dict of {category_name: compiled_pattern}
        assert isinstance(typed, dict)
        for _cat, pat in typed.items():
            assert isinstance(pat, re.Pattern)
        # Category keys are from {"technical_terms", "proper_nouns", "general_terms"}
        assert all(k in {"technical_terms", "proper_nouns", "general_terms"} for k in typed)


class TestAddRemoveKeyword:
    """Dynamic keyword list mutation."""

    def test_add_keyword(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.set_keywords(["ransomware"])
        stemmer.add_keyword("phishing")
        assert stemmer.compiled_pattern is not None
        assert stemmer.compiled_pattern.search("phishing")
        assert stemmer.compiled_pattern.search("ransomware")

    def test_remove_keyword(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.set_keywords(["ransomware", "phishing"])
        stemmer.remove_keyword("ransomware")
        assert stemmer.compiled_pattern is not None
        assert not stemmer.compiled_pattern.search("ransomware")
        assert stemmer.compiled_pattern.search("phishing")

    def test_cache_invalidation_on_add(self, stemmer: DynamicKeywordStemmer) -> None:
        """Adding a keyword should invalidate and rebuild the compiled pattern."""
        stemmer.set_keywords(["old"])
        old_pat = stemmer.compiled_pattern
        stemmer.add_keyword("new")
        # Cache was invalidated — accessing compiled_pattern rebuilds it
        assert stemmer.compiled_pattern is not old_pat


class TestFindMatches:
    """Match extraction from text — returns list[MatchInfo] Pydantic objects."""

    def test_find_matches_exact(self, stemmer_exact: DynamicKeywordStemmer) -> None:
        stemmer_exact.set_keywords(["ransomware"])
        matches = stemmer_exact.find_matches("The ransomware attack.")
        assert len(matches) >= 1
        m = matches[0]
        assert m.keyword == "ransomware"
        assert m.match == "ransomware"
        assert isinstance(m.start, int)
        assert isinstance(m.end, int)
        assert m.start < m.end

    def test_find_matches_stemmed(self, stemmer: DynamicKeywordStemmer) -> None:
        # STEM mode: keyword "ransomware" + suffix "s" should match "ransomwares"
        stemmer.set_keywords(["ransomware"])
        matches = stemmer.find_matches("The ransomwares attacked again.")
        assert len(matches) >= 1
        assert any(m.stemmed for m in matches)

    def test_find_matches_no_keywords(self, stemmer: DynamicKeywordStemmer) -> None:
        matches = stemmer.find_matches("some text")
        assert matches == []


class TestCaseSensitivity:
    """Case-(in)sensitive matching."""

    def test_case_sensitive(self) -> None:
        s = DynamicKeywordStemmer(case_sensitive=True)
        s.set_keywords(["Ransomware"])
        assert len(s.find_matches("Ransomware is bad.")) >= 1
        assert len(s.find_matches("ransomware is bad.")) == 0

    def test_case_insensitive(self, stemmer: DynamicKeywordStemmer) -> None:
        stemmer.set_keywords(["ransomware"])
        assert len(stemmer.find_matches("RANSOMWARE is bad.")) >= 1


class TestSpecialCharacters:
    """Special regex characters in keywords are escaped."""

    def test_special_characters_escaped(self, stemmer: DynamicKeywordStemmer) -> None:
        # Verify keywords with regex-special chars compile without PatternCompileError.
        # \b word boundaries around non-word-char-terminated tokens (C++, [test])
        # mean they won't match in typical text — the point is they DON'T throw.
        kws = ["C++", "[test]", "a.b", "x*y"]
        stemmer.set_keywords(kws)
        assert stemmer.compiled_pattern is not None
        # The escaped chars must appear literally in the pattern string
        assert r"C\+\+" in stemmer.compiled_pattern.pattern
        assert r"\[test\]" in stemmer.compiled_pattern.pattern
        # Calling search on arbitrary text must not raise
        _ = stemmer.compiled_pattern.search("using C++ and [test] cases")


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

    def test_registry_with_stemmer(self, registry_with_stemmer: KeywordPatternRegistry) -> None:
        assert registry_with_stemmer.all_patterns is not None

    def test_extract_all_returns_dict(self, registry_with_stemmer: KeywordPatternRegistry) -> None:
        text = "The ransomware used a CVE exploit."
        results = registry_with_stemmer.extract_all(text)
        assert isinstance(results, dict)

    def test_extract_all_dynamic_keyword_matches(
        self,
        registry_with_stemmer: KeywordPatternRegistry,
        sample_keywords: list[str],
    ) -> None:
        # regenerate_dynamic_patterns must be called before dynamic matches work
        registry_with_stemmer.regenerate_dynamic_patterns(sample_keywords)
        text = "The ransomware used a CVE exploit."
        results = registry_with_stemmer.extract_all(text)
        all_matches = [m for matches in results.values() for m in matches]
        assert isinstance(all_matches, list)
        assert any(isinstance(m, str) for m in all_matches)
        assert any("ransomware" in m.lower() or "exploit" in m.lower() for m in all_matches)

    def test_regenerate_dynamic_patterns(
        self, registry: KeywordPatternRegistry, sample_keywords: list[str]
    ) -> None:
        registry.regenerate_dynamic_patterns(sample_keywords)
        results = registry.extract_all("ransomware and CVE")
        assert isinstance(results, dict)
