from __future__ import annotations


class InsightExtractorError(Exception):
    """Base exception for the insight_extractor package."""

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.details: dict[str, object] = details if details is not None else {}


class ConfigLoadError(InsightExtractorError, ValueError):
    """Raised when configuration file loading fails."""


class ModelLoadError(InsightExtractorError, RuntimeError):
    """Raised when the BERT model fails to load."""


class StateLoadError(InsightExtractorError):
    """Raised when state file loading fails."""


class PatternCompileError(InsightExtractorError):
    """Raised when regex pattern compilation fails."""
