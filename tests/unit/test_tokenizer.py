"""Tests for SentenceTokenizer without downloading HuggingFace assets."""

from __future__ import annotations

import pytest

import insight_extractor
from insight_extractor.stemmer import DynamicKeywordStemmer
from insight_extractor.tokenizer import SentenceTokenizer


class FakeTokenizer:
    def encode(self, text: str, *, add_special_tokens: bool = False) -> list[int]:
        del add_special_tokens
        return list(range(len(text.split())))

    def decode(self, tokens: list[int], *, skip_special_tokens: bool = True) -> str:
        del skip_special_tokens
        return " ".join(f"tok{i}" for i in tokens)


def test_lazy_root_imports() -> None:
    assert insight_extractor.DynamicKeywordStemmer is DynamicKeywordStemmer
    with pytest.raises(AttributeError):
        getattr(insight_extractor, "MissingThing")


def test_count_tokens_uses_loaded_tokenizer() -> None:
    tokenizer = SentenceTokenizer()
    tokenizer._tokenizer = FakeTokenizer()

    assert tokenizer.count_tokens("one two three") == 3


def test_chunk_text_short_and_long() -> None:
    tokenizer = SentenceTokenizer()
    tokenizer._tokenizer = FakeTokenizer()

    assert tokenizer.chunk_text("one two", max_tokens=5) == ["one two"]
    assert tokenizer.chunk_text("one two three four five six", max_tokens=3, overlap=1) == [
        "tok0 tok1 tok2",
        "tok2 tok3 tok4",
        "tok4 tok5",
    ]


def test_tokenize_sentences_and_empty_text() -> None:
    tokenizer = SentenceTokenizer()
    tokenizer._tokenizer = FakeTokenizer()

    assert tokenizer.tokenize_sentences("") == []
    assert tokenizer.tokenize_sentences("No punctuation") == ["No punctuation"]
    assert tokenizer.tokenize_sentences("First sentence. Second sentence!") == [
        "First sentence.",
        "Second sentence!",
    ]
