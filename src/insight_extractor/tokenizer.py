"""Sentence tokenization using HuggingFace AutoTokenizer."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from transformers import AutoTokenizer

logger = logging.getLogger("insight_extractor")


class SentenceTokenizer:
    """Sentence-level tokenization using the model's HuggingFace tokenizer."""

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        self._tokenizer: AutoTokenizer | None = None

    @property
    def tokenizer(self) -> AutoTokenizer:
        """Lazy-load the AutoTokenizer on first access."""
        if self._tokenizer is None:
            from transformers import AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)  # type: ignore[no-untyped-call]
        return self._tokenizer

    def count_tokens(self, text: str) -> int:
        """Return the number of tokens for text."""
        return len(self.tokenizer.encode(text, add_special_tokens=False))  # type: ignore[attr-defined]

    def chunk_text(self, text: str, max_tokens: int = 512, overlap: int = 50) -> list[str]:
        """
        Split text into chunks of max_tokens with sliding window overlap.
        Uses the model's tokenizer for accurate token counting.
        """
        tokens = self.tokenizer.encode(text, add_special_tokens=False)  # type: ignore[attr-defined]
        if len(tokens) <= max_tokens:
            return [text]

        chunks: list[str] = []
        start = 0
        while start < len(tokens):
            end = min(start + max_tokens, len(tokens))
            chunk_tokens = tokens[start:end]
            chunk_text = self.tokenizer.decode(chunk_tokens, skip_special_tokens=True)  # type: ignore[attr-defined]
            chunks.append(chunk_text)
            start += max_tokens - overlap
            if start >= end:
                break
        return chunks

    def tokenize_sentences(self, text: str, max_tokens: int = 512) -> list[str]:
        """
        Split text into sentences using regex, then ensure each sentence
        is within the max_tokens budget by chunking oversized sentences.
        """
        # Split on sentence boundaries
        raw_sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
        if not raw_sentences:
            return [text] if text.strip() else []

        result: list[str] = []
        for sentence in raw_sentences:
            if self.count_tokens(sentence) > max_tokens:
                result.extend(self.chunk_text(sentence, max_tokens=max_tokens, overlap=50))
            else:
                result.append(sentence)
        return result
