from __future__ import annotations


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
