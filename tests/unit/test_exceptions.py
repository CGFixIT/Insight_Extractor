"""Tests for the exception hierarchy."""
from __future__ import annotations

import pytest

from insight_extractor.exceptions import (
    ConfigLoadError,
    InsightExtractorError,
    ModelLoadError,
    PatternCompileError,
    StateLoadError,
)


class TestExceptionHierarchy:
    """Verify the custom exception classes behave correctly."""

    def test_exception_hierarchy(self) -> None:
        """All custom exceptions inherit from InsightExtractorError."""
        assert issubclass(ConfigLoadError, InsightExtractorError)
        assert issubclass(ModelLoadError, InsightExtractorError)
        assert issubclass(StateLoadError, InsightExtractorError)
        assert issubclass(PatternCompileError, InsightExtractorError)

    def test_exception_message(self) -> None:
        """The message passed at construction is stored on the instance."""
        msg = "something went wrong"
        err = InsightExtractorError(msg)
        assert str(err) == msg

    def test_exception_details(self) -> None:
        """A details dict can be attached and accessed."""
        details = {"key": "value", "count": 42}
        err = InsightExtractorError("boom", details=details)
        assert err.details is details
        assert err.details["key"] == "value"

    def test_exception_details_default(self) -> None:
        """When no details are provided, the default is an empty dict."""
        err = InsightExtractorError("boom")
        assert err.details == {}


class TestConfigLoadError:
    """ConfigLoadError is also a ValueError."""

    def test_is_value_error(self) -> None:
        err = ConfigLoadError("bad config")
        assert isinstance(err, ValueError)
        assert isinstance(err, InsightExtractorError)

    def test_message_and_details(self) -> None:
        err = ConfigLoadError("parse failed", details={"line": 3})
        assert str(err) == "parse failed"
        assert err.details == {"line": 3}


class TestModelLoadError:
    """ModelLoadError is also a RuntimeError."""

    def test_is_runtime_error(self) -> None:
        err = ModelLoadError("model not found")
        assert isinstance(err, RuntimeError)
        assert isinstance(err, InsightExtractorError)

    def test_message(self) -> None:
        err = ModelLoadError("cuda oom")
        assert str(err) == "cuda oom"


class TestStateLoadError:
    """StateLoadError persistence-related errors."""

    def test_is_insight_extractor_error(self) -> None:
        err = StateLoadError("file missing")
        assert isinstance(err, InsightExtractorError)

    def test_message(self) -> None:
        err = StateLoadError("corrupt json")
        assert str(err) == "corrupt json"


class TestPatternCompileError:
    """PatternCompileError for regex compilation failures."""

    def test_is_insight_extractor_error(self) -> None:
        err = PatternCompileError("invalid group")
        assert isinstance(err, InsightExtractorError)

    def test_message(self) -> None:
        err = PatternCompileError("unbalanced paren")
        assert str(err) == "unbalanced paren"

    def test_details(self) -> None:
        err = PatternCompileError("bad pattern", details={"pattern": "[invalid"})
        assert err.details["pattern"] == "[invalid"
