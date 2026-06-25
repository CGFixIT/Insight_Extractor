# Plan: Full Project Refactor — insight_extractor

## Goal
Transform the single script into a complete, modern Python 3.12+ project with Pydantic models, proper tokenization, tests, and packaging.

## Deliverables

### Project Structure
```
/mnt/agents/output/insight_extractor/
├── pyproject.toml              # Modern packaging (PEP 621)
├── requirements.txt            # Runtime deps
├── constraints.txt             # Pinned versions
├── README.md                   # Project documentation
├── src/
│   └── insight_extractor/
│       ├── __init__.py         # Package init with exports
│       ├── __main__.py         # python -m insight_extractor
│       ├── extractor.py        # Core InsightExtractor class
│       ├── stemmer.py          # DynamicKeywordStemmer + KeywordPatternRegistry
│       ├── models.py           # Pydantic models (ExtractResult, etc.)
│       ├── config.py           # Enums (StemMode, KeywordCategory, PatternLabel)
│       ├── constants.py        # THREAD_SEEDS, REGEX_PATTERNS
│       ├── tokenizer.py        # SentenceTokenizer using model tokenizer
│       ├── exceptions.py       # Custom exceptions
│       └── utils.py            # Logging setup, helpers
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # pytest fixtures
│   ├── test_stemmer.py         # Unit: DynamicKeywordStemmer
│   ├── test_registry.py        # Unit: KeywordPatternRegistry
│   ├── test_extractor.py       # Unit + integration: InsightExtractor
│   ├── test_tokenizer.py       # Unit: SentenceTokenizer
│   ├── test_models.py          # Unit: Pydantic model validation
│   └── test_e2e.py             # End-to-end: full pipeline
└── insights_extracted.md       # Output file (generated)
```

## Stage 1: Write Project Spec (SPEC.md)
- Define all interfaces, models, enums
- Define file layout and module boundaries

## Stage 2: Implement Source Code (Parallel)
- **Agent A**: `models.py`, `config.py`, `constants.py`, `exceptions.py`, `__init__.py`
- **Agent B**: `stemmer.py` (DynamicKeywordStemmer + KeywordPatternRegistry)
- **Agent C**: `tokenizer.py`, `utils.py`
- **Agent D**: `extractor.py` (main InsightExtractor) + `__main__.py`

## Stage 3: Config Files (Parallel)
- **Agent E**: `pyproject.toml`, `requirements.txt`, `constraints.txt`, `README.md`

## Stage 4: Test Suite
- **Agent F**: All test files under `tests/`

## Stage 5: Validation
- Syntax check, import check, test discovery

## Key Requirements
1. **Pydantic models**: `ExtractResult`, `MatchInfo`, `KeywordStats`, `SemanticHit`, `SentenceScore` — all with validation
2. **Proper sentence tokenization**: Use `transformers.AutoTokenizer` from the model's tokenizer for sentence splitting
3. **Output to `insights_extracted.md`**: Markdown-formatted results file in working folder
4. **Python 3.12+**: `type` aliases, `|` unions, `match`/`case`, `StrEnum`, `tomllib`
5. **pyproject.toml**: PEP 621 compliant with `[build-system]`, `[project]`, `[project.optional-dependencies]` (dev/test)
6. **pytest**: fixtures, parametrized tests, tmp_path, monkeypatch
