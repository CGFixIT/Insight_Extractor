"""Fast unit coverage for InsightExtractor without downloading model weights."""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from insight_extractor.exceptions import ConfigLoadError, ModelLoadError, StateLoadError
from insight_extractor.extractor import InsightExtractor


class FakeModel:
    def encode(
        self,
        texts: str | list[str],
        *_args: Any,
        **_kwargs: Any,
    ) -> np.ndarray[Any, np.dtype[np.float64]]:
        items = [texts] if isinstance(texts, str) else texts
        rows = []
        for idx, _item in enumerate(items, start=1):
            rows.append([float(idx), 1.0, 0.5, 0.25])
        return np.array(rows, dtype=np.float64)


class FakeTokenizer:
    def tokenize_sentences(self, text: str, *, max_tokens: int = 512) -> list[str]:
        del max_tokens
        return [part.strip() for part in text.split(".") if len(part.strip()) > 10]


def build_extractor(tmp_path: Path) -> InsightExtractor:
    extractor = InsightExtractor(
        seed_keywords=["ransomware", "CVE", "exploit"],
        output_dir=tmp_path,
        similarity_threshold=0.0,
        dynamic_expansion_top_n=3,
    )
    extractor._model = FakeModel()
    extractor._tokenizer = FakeTokenizer()
    return extractor


def test_full_pipeline_with_fake_model(tmp_path: Path) -> None:
    extractor = build_extractor(tmp_path)
    text = (
        "Ransomware operators exploited CVE-2026-1234 during a phishing campaign. "
        "The exploit chain touched 192.168.1.10 and ransom@example.com."
    )

    result = extractor.extract(text)

    assert result.word_count > 0
    assert "CVE_ID" in result.regex_entities
    assert "IP_ADDRESS" in result.regex_entities
    assert result.dynamic_keyword_matches
    assert result.semantic_keywords
    assert result.key_sentences
    assert result.keyword_stats.total_keywords == result.total_tracked_keywords

    md_path = extractor.save_results_to_markdown(result)
    assert md_path.exists()
    assert "Insight Extraction Results" in md_path.read_text(encoding="utf-8")


def test_regex_and_dynamic_can_run_without_model(tmp_path: Path) -> None:
    extractor = InsightExtractor(
        seed_keywords=["ransomware"],
        enable_dynamic_regex=True,
        output_dir=tmp_path,
    )
    text = "Ransomware at 10.0.0.1 references CVE-2026-9999 and port 4444."

    assert extractor.extract_regex_entities(text)["CVE_ID"] == ["CVE-2026-9999"]
    assert extractor.extract_regex_entities(text)["PORT_NUMBER"] == ["4444"]
    assert extractor.extract_dynamic_entities(text)


def test_config_loads_supported_formats(tmp_path: Path) -> None:
    toml_file = tmp_path / "config.toml"
    toml_file.write_text('seed_keywords = ["tomlkw"]\nsimilarity_threshold = 0.25\n')
    assert InsightExtractor(config_path=toml_file).similarity_threshold == 0.25

    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("seed_keywords:\n  - yamlkw\nstem_mode: exact\n")
    assert "yamlkw" in InsightExtractor(config_path=yaml_file).thread_keywords

    json_file = tmp_path / "config.json"
    json_file.write_text(json.dumps({"seed_keywords": ["jsonkw"]}))
    assert "jsonkw" in InsightExtractor(config_path=json_file).thread_keywords


def test_bad_config_format_raises(tmp_path: Path) -> None:
    config_file = tmp_path / "config.ini"
    config_file.write_text("seed_keywords=bad")

    with pytest.raises(ConfigLoadError):
        InsightExtractor._load_config(config_file)


def test_state_roundtrip_and_bad_state(tmp_path: Path) -> None:
    extractor = build_extractor(tmp_path)
    state_file = tmp_path / "state.json"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        extractor.save_state(state_file)
        restored = InsightExtractor(seed_keywords=[], output_dir=tmp_path)
        restored._model = FakeModel()
        assert restored.load_state(state_file) is True

    assert not [warning for warning in caught if issubclass(warning.category, DeprecationWarning)]
    assert "ransomware" in restored.thread_keywords

    bad_state = tmp_path / "bad.json"
    bad_state.write_text("{not json")
    with pytest.raises(StateLoadError):
        restored.load_state(bad_state)


def test_empty_paths_return_empty_results(tmp_path: Path) -> None:
    extractor = InsightExtractor(seed_keywords=[], enable_dynamic_regex=False, output_dir=tmp_path)

    assert extractor.extract_dynamic_entities("anything") == {}
    assert extractor.extract_semantic_keywords("anything") == []
    assert extractor.extract_key_sentences("short") == []
    assert extractor.update_thread_keywords("plain text", auto_expand=False) == []
    assert extractor.load_state(tmp_path / "missing.json") is False


def test_model_load_failure_is_wrapped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail_load(_model_name: str) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr("insight_extractor.extractor.SentenceTransformer", fail_load)
    extractor = InsightExtractor(seed_keywords=[], output_dir=tmp_path)

    with pytest.raises(ModelLoadError):
        _ = extractor.model
