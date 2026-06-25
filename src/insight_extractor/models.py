from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


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
