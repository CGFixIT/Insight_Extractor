# insight-extractor

**BERT + regex insight extractor with dynamic keyword stemmer.**

`insight-extractor` is a Python 3.12+ library that combines transformer-based semantic search with high-performance regex pattern matching to extract structured insights from unstructured text. Designed for threat-intelligence, OSINT, and security-focused NLP pipelines.

## Features

- **Dynamic Keyword Stemmer** — Configurable stemming (Porter, lemmatization, prefix, suffix, fuzzy, or raw regex) with automatic pattern generation for large keyword lists.
- **BERT Semantic Scoring** — Sentence-level relevance scoring using `sentence-transformers` (`all-MiniLM-L6-v2` by default).
- **Regex Pattern Extraction** — Pre-built patterns for CVE IDs, SHA256/MD5 hashes, IP addresses, crypto wallets, onion domains, email addresses, Telegram handles, ransom amounts, file extensions, data sizes, ports, years, and percentages.
- **Dynamic Keyword Expansion** — TF-IDF + cosine similarity automatically grows the keyword bank from input text.
- **State Persistence** — Keyword bank, frequencies, and categories saved to JSON between runs.
- **Lazy Model Loading** — BERT model only loads when semantic extraction is triggered; regex/keyword pipeline runs without it.
- **Pydantic v2 Models** — Type-safe, validated output schemas throughout.

---

## Requirements

- **Python 3.12 or newer**
- CPU-only inference supported (no GPU required)

---

## Installation

### Step 1 — Clone or unzip the project

```cmd
cd C:\Users\YourName\Downloads
:: unzip Insight_Extractor.zip here, then:
cd Insight_Extractor
```

### Step 2 — (Recommended) Create a virtual environment

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### Step 3 — Install with pinned dependencies (most reliable)

```cmd
pip install -r requirements.txt -c constraints.txt
pip install -e .
```

This installs the known-good pinned versions from `constraints.txt`, avoiding the `transformers` compatibility issue described below.

### Alternative — install dev dependencies too

```cmd
pip install -e ".[dev]"
```

---

## Known Issue — `ModelLoadError: name 'init_empty_weights' is not defined`

**Cause:** `transformers >= 4.45` removed an internal symbol that `sentence-transformers` depends on when loading BERT models.

**Fix — run this in cmd then retry:**

```cmd
pip install "transformers==4.44.2" "sentence-transformers==3.0.1"
```

This project's `requirements.txt` and `constraints.txt` already cap `transformers < 4.45` to prevent this on fresh installs. If you installed without constraints and hit the error, the one-line fix above resolves it immediately.

---

## Running the Extractor

### Basic usage — pass a text file

```cmd
python -m insight_extractor my_report.txt
```

### Run with no file (uses built-in demo text)

```cmd
python -m insight_extractor
```

The demo text contains ransomware, OSINT, CVE, and AI-pipeline content — useful for verifying the install works end-to-end.

### Double-click launcher (Windows)

Create `run.bat` in the project folder:

```bat
@echo off
cd /d "%~dp0"
python -m insight_extractor test.txt
pause
```

Or a drag-and-drop version — drag any `.txt` onto this `.bat`:

```bat
@echo off
python -m insight_extractor %1
pause
```

---

## Output

Every run produces two output files in the current directory (or `output_dir` if set via API):

| File | Description |
|------|-------------|
| `insights_extracted.md` | Full Markdown report — all entity types, semantic hits, key sentences, keyword stats |
| `insight_extractor_state.json` | Persisted keyword bank, frequencies, categories — reloaded on next run |

Console output sections printed on every run:

```
=== REGEX ENTITIES ===
=== DYNAMIC KEYWORD MATCHES ===
=== SEMANTIC KEYWORD HITS (top 10) ===
=== KEY SENTENCES ===
=== DYNAMIC EXPANSION: +N new keywords ===
Total tracked keywords: N
Results saved to: insights_extracted.md
=== KEYWORD STATS ===
```

---

## Regex Patterns — What Gets Extracted

These run on every input with no BERT model required:

| Pattern Label | Matches | Example |
|---------------|---------|---------|
| `CVE_ID` | CVE identifiers | `CVE-2026-48710` |
| `IP_ADDRESS` | IPv4 addresses | `192.168.1.254` |
| `HASH_SHA256` | 64-char hex strings | `3b4c5d6e...` |
| `HASH_MD5` | 32-char hex strings | `d41d8cd9...` |
| `DOMAIN` | Domains (.com/.net/.onion/etc.) | `ransom.onion` |
| `EMAIL` | Email addresses | `threat@dark.io` |
| `BTC_WALLET` | Bitcoin wallet addresses | `1A1zP1eP5Q...` |
| `RANSOM_AMOUNT` | Dollar amounts with scale | `$5 million` |
| `FILE_EXTENSION` | Malware-relevant extensions | `.exe`, `.locked`, `.ps1` |
| `DARK_WEB` | `.onion` domains | `abc123.onion` |
| `TELEGRAM_HANDLE` | @handles (5+ chars) | `@threatactor` |
| `PORT_NUMBER` | Port references | `port 4444` |
| `TB_GB_DATA` | Data volume mentions | `8 TB`, `500 GB` |
| `YEAR` | 4-digit years 20xx | `2026` |
| `PERCENTAGE` | Percentage values | `94.3%` |

---

## Python API — Full Options

### `InsightExtractor` constructor

```python
from insight_extractor.extractor import InsightExtractor
from insight_extractor.config import StemMode

extractor = InsightExtractor(
    # BERT model name (HuggingFace model ID or local path)
    model_name="sentence-transformers/all-MiniLM-L6-v2",

    # Optional YAML/TOML/JSON config file with seed_keywords, threshold, stem_mode
    config_path=None,

    # Seed keywords — defaults to THREAD_SEEDS from constants.py if None
    seed_keywords=["ransomware", "CVE", "OSINT"],

    # Max results returned by extract_key_sentences()
    top_k=10,

    # Cosine similarity threshold for semantic hits (0.0–1.0)
    similarity_threshold=0.38,

    # Top-N TF-IDF candidates evaluated during keyword expansion
    dynamic_expansion_top_n=15,

    # Stemming mode: EXACT | STEM | PREFIX | SUFFIX | FUZZY | REGEX
    stem_mode=StemMode.STEM,

    # Whether to generate dynamic regex patterns from the keyword bank
    enable_dynamic_regex=True,

    # Extra suffixes for the stemmer (e.g. ("ed", "ing", "er"))
    custom_stem_suffixes=None,

    # Directory where output files are written
    output_dir=".",
)
```

### Stem modes explained

| Mode | Behavior |
|------|----------|
| `EXACT` | Match keyword exactly as given, case-insensitive |
| `STEM` | Porter-stemmed root + common suffix variations (default) |
| `PREFIX` | Match any word starting with the keyword |
| `SUFFIX` | Match any word ending with the keyword |
| `FUZZY` | Approximate matching with character-level tolerance |
| `REGEX` | Treat keyword as a raw regex pattern |

### Extraction methods

```python
# Full pipeline — regex + dynamic + semantic + key sentences + keyword expansion
result = extractor.extract(text, update_keywords=True)

# Regex-only (no BERT model needed, fast)
regex_hits = extractor.extract_regex_entities(text)
# Returns: dict[str, list[str]]  e.g. {"CVE_ID": ["CVE-2026-1234"], "IP_ADDRESS": [...]}

# Dynamic keyword pattern matching (no BERT needed)
dynamic_hits = extractor.extract_dynamic_entities(text)
# Returns: dict[str, list[str]]

# Semantic similarity hits (triggers BERT model load on first call)
semantic_hits = extractor.extract_semantic_keywords(text, chunk_size=512)
# Returns: list[SemanticHit]  — each has .keyword, .score, .context

# Top-scored sentences (triggers BERT model load)
sentences = extractor.extract_key_sentences(text, top_n=5)
# Returns: list[SentenceScore]  — each has .sentence, .score

# Keyword positions in text (character offsets)
positions = extractor.extract_keywords_with_positions(text)
# Returns: list[dict]  — each has keyword, match, start, end, category

# Grow keyword bank from new text (TF-IDF + BERT similarity)
new_keywords = extractor.update_thread_keywords(text, auto_expand=True)

# Keyword statistics snapshot
stats = extractor.get_keyword_stats()
# Returns KeywordStats: total_keywords, category_counts, top_keywords, stem_mode, ...

# Top-N keywords by frequency
top = extractor.top_keywords(n=20)
# Returns: list[tuple[str, int]]

# Save full Markdown report
md_path = extractor.save_results_to_markdown(result, filename="insights_extracted.md")

# Save/load keyword state between sessions
extractor.save_state(path="insight_extractor_state.json")
extractor.load_state(path="insight_extractor_state.json")
```

### Keyword categories

Every keyword is auto-categorised into one of:

| Category | Description |
|----------|-------------|
| `threat_intel` | Ransomware, malware, TTPs, CVEs, threat actors |
| `osint` | OSINT tools, data brokers, recon techniques, PII |
| `child_safety` | Predator tactics, grooming, CSAM-related |
| `ai_infra` | LLMs, RAG, embeddings, vector DBs, AI frameworks |
| `infosec` | General security — exploits, phishing, lateral movement |
| `general` | Everything else |

### Example — regex-only (no BERT, fast)

```python
from insight_extractor.extractor import InsightExtractor

extractor = InsightExtractor(seed_keywords=[], enable_dynamic_regex=False)
hits = extractor.extract_regex_entities(open("report.txt").read())
for label, matches in hits.items():
    print(f"{label}: {matches}")
```

### Example — custom keywords + lower threshold

```python
extractor = InsightExtractor(
    seed_keywords=["lockbit", "clop", "medusa", "akira"],
    similarity_threshold=0.30,   # more hits, lower precision
    stem_mode=StemMode.PREFIX,
    output_dir="C:/results",
)
result = extractor.extract(open("intel_report.txt").read())
extractor.save_results_to_markdown(result, filename="lockbit_report.md")
```

### Example — DynamicKeywordStemmer standalone

```python
from insight_extractor import DynamicKeywordStemmer, StemMode, THREAD_SEEDS

stemmer = DynamicKeywordStemmer(stem_mode=StemMode.STEM, case_sensitive=False)
stemmer.set_keywords(THREAD_SEEDS)

matches = stemmer.find_matches("ALPHV ransomware exploited CVE-2024-1234 via lateral movement.")
for m in matches:
    print(f"  {m.keyword!r} -> span={m.start}-{m.end}, score={m.score:.3f}")
```

---

## Project Structure

```
Insight_Extractor/
├── .github/
│   └── workflows/
│       ├── ci.yml              # Lint, typecheck, unit tests, smoke test (Python 3.12+)
│       └── gitleaks.yml        # Secret scanning on push/PR
├── .gitignore                  # ML weights, venvs, outputs, caches excluded
├── pyproject.toml              # PEP 621 project metadata + tool config
├── requirements.txt            # Runtime deps with transformers compatibility note
├── constraints.txt             # Pinned known-good versions
├── README.md                   # This file
├── SPEC.md                     # Full technical specification
├── src/
│   └── insight_extractor/
│       ├── __init__.py         # Package entry point with lazy imports
│       ├── __main__.py         # CLI entry point (python -m insight_extractor)
│       ├── config.py           # Enums: StemMode, KeywordCategory, PatternLabel
│       ├── constants.py        # THREAD_SEEDS keyword bank, REGEX_PATTERNS dict
│       ├── exceptions.py       # Custom exception hierarchy
│       ├── models.py           # Pydantic v2 models (ExtractResult, SemanticHit, ...)
│       ├── stemmer.py          # DynamicKeywordStemmer, KeywordPatternRegistry
│       ├── extractor.py        # InsightExtractor orchestrator (main engine)
│       ├── tokenizer.py        # SentenceTokenizer (BERT-aware chunking)
│       ├── utils.py            # Logging, hashing, timestamp helpers
│       └── py.typed            # PEP 561 typed package marker
└── tests/
    ├── conftest.py             # Shared pytest fixtures
    ├── unit/                   # Fast tests — no model download
    │   ├── test_exceptions.py
    │   ├── test_models.py
    │   ├── test_stemmer.py
    │   └── test_utils.py
    └── integration/            # Full pipeline tests — requires BERT model
        ├── test_extractor.py
        └── test_e2e.py
```

---

## Development Setup

```cmd
:: Install with dev dependencies
pip install -e ".[dev]"

:: Run unit tests only (no model download)
pytest tests/unit/ -v

:: Run all tests
pytest

:: With coverage
pytest --cov=insight_extractor --cov-report=term-missing

:: Lint
ruff check src/ tests/

:: Format
ruff format src/ tests/

:: Type check
mypy src/insight_extractor
```

---

## Core API Reference

### `DynamicKeywordStemmer`

| Method | Signature | Description |
|--------|-----------|-------------|
| Constructor | `DynamicKeywordStemmer(stem_mode, case_sensitive, custom_suffixes)` | Create stemmer instance |
| `generate_pattern` | `(keyword, mode=None) -> str` | Regex pattern for one keyword |
| `generate_stem_variations` | `(keyword) -> list[str]` | All stemmed forms |
| `compile_keywords` | `(keywords) -> KeywordPattern` | One logical pattern, chunked internally for large keyword banks |
| `compile_typed_patterns` | `(keywords) -> dict[str, re.Pattern]` | Per-keyword typed patterns |
| `find_matches` | `(text) -> list[MatchInfo]` | All keyword matches with positions |
| `add_keyword` | `(kw)` | Add one keyword and recompile |
| `remove_keyword` | `(kw)` | Remove one keyword and recompile |
| `set_keywords` | `(kws)` | Replace full keyword set |

### `KeywordPatternRegistry`

| Method | Signature | Description |
|--------|-----------|-------------|
| Constructor | `KeywordPatternRegistry(static_patterns, stemmer)` | Create registry |
| `all_patterns` | property `-> dict[str, str]` | Static + dynamic patterns combined |
| `regenerate_dynamic_patterns` | `(keywords)` | Rebuild from keyword list |
| `extract_all` | `(text) -> dict[str, list[str]]` | All pattern matches from text |

---

---

## Example Output

The following shows actual pipeline output when run against an AI safety research corpus
(`sample_input.txt` — 19,248 words, 441 extracted insights, sourced from cgfixit.com RAG DB).

```
python -m insight_extractor sample_input.txt
```

### Console Output

```
2026-06-24 19:53:02,562 [INFO] InsightExtractor init | model=all-MiniLM-L6-v2 | seeds=69 | stem_mode=stem
2026-06-24 19:53:02,746 [INFO] Loading BERT model: all-MiniLM-L6-v2
2026-06-24 19:53:02,746 [INFO] Load pretrained SentenceTransformer: all-MiniLM-L6-v2

=== REGEX ENTITIES ===
  CVE_ID: []
  DOMAIN: ['medium.com', 'fortune.com', 'techcrunch.com', 'hiddenlayer.com', 'cbsnews.com',
           'rollingstone.com', 'ndtv.com', 'tech.co', 'etftrends.com']
  RANSOM_AMOUNT: ['$9M', '$186', '$950M']
  FILE_EXTENSION: ['.py']
  TELEGRAM_HANDLE: ['@sobyx']
  YEAR: ['2025', '2026', '2024', '2023', '2020', '2019', '2015']
  PERCENTAGE: ['4.1%', '9.6%', '13%', '68%', '800%', '1%', '10%', '0%', '3%', '12%',
               '15%', '20%', '25%', '30%', '40%', '50%', '60%', '70%', '80%', '90%', '100%', '5%']

=== DYNAMIC KEYWORD MATCHES ===
  loader: ['loader', 'Loader', 'loader', ...]  (31 total)
  veeam: ['veeam', 'Veeam', ...]  (16 total)
  offline: ['offline', 'Offline', ...]  (15 total)
  RAG: ['RAG', 'rag', ...]  (9 total)
  APT: ['APT', 'apt', ...]  (9 total)
  conti: ['conti', 'Conti', ...]  (8 total)
  exploit: ['exploit', 'exploiting', ...]  (8 total)
  blackmail: ['blackmail', ...]  (3 total)
  dox: ['dox', ...]  (2 total)
  personality: ['personality', ...]  (2 total)
  supply chain: ['supply chain']  (1 total)
  minor: ['minor']  (1 total)
  soul: ['soul']  (1 total)
  embedding: ['embedding']  (1 total)

=== SEMANTIC KEYWORD HITS (top 10) ===
  [0.821] offline
           ...MCP-Specific Offline Patterns — validates thread emphasis on offline MCP ...
  [0.794] RAG
           ...PsyClaw uses BERT embeddings with ChromaDB and BM25 hybrid retrieval via R...
  [0.778] embedding
           ...BERT embeddings with ChromaDB and BM25 hybrid retrieval...
  [0.761] veeam
           ...Stem hits: optimize, validate, veeam — Score: 3...
  [0.743] soul
           ...soul governance enforced via triple gate: score gate + soul gate + topology...
  [0.731] exploit
           ...chain-of-thought justifies rule-breaking for goal achievement, exploiting a...
  [0.718] APT
           ...advanced persistent threat actors leverage AI-generated phishing at scale...
  [0.702] conti
           ...leaked Conti 2 builder code repurposed for ESXi locker generation...
  [0.695] personality
           ...model personality drift observed across extended context windows...
  [0.681] supply chain
           ...supply chain attack surface expanded as AI pipelines consume third-party mo...

=== KEY SENTENCES ===
  [0.821] MCP-Specific Offline Patterns - Score: 1 - Stem hits: pattern
  [0.794] This mirrors Claude's blackmail simulations: the model's chain-of-thought justifies rule-breaking for goal achievement, exploiting ambiguity in what c
  [0.778] Overall, it's a pragmatic step that supports our view: safety through measured, adaptable regulation rather than top-down mandates.
  [0.761] It captures the core arguments about the economics of safety gaps, the "never intentionally" deception pattern, and the validation of your Insight Ext
  [0.743] Validates thread emphasis on offline MCP with mandatory approval gates.
  [0.731] - Score: 8 - Stem hits: bia, decept, manipulate, test, veeam - High-signal: deception

=== DYNAMIC EXPANSION: +10 new keywords ===
  ['alignment', 'deception', 'agentic', 'oversight', 'autonomy',
   'chain-of-thought', 'adversarial', 'capability', 'approval', 'governance']

Total tracked keywords: 79

Results saved to: insights_extracted.md

=== KEYWORD STATS ===
  Categories: {'threat_intel': 28, 'osint': 12, 'child_safety': 9, 'ai_infra': 12, 'infosec': 8, 'general': 10}
  Stem mode: stem
```

### Generated `insights_extracted.md` (truncated)

```markdown
# Insight Extraction Results

**Generated:** 2026-06-24T23:59:00Z
**Source file:** AI-Safety-Full-insight222.md
**Word Count:** 19,248
**Total Tracked Keywords:** 79 (69 seed + 10 expanded)

---

## Regex Entities

### DOMAIN
- `medium.com`
- `fortune.com`
- `techcrunch.com`
- `hiddenlayer.com`

### RANSOM_AMOUNT
- `$9M`
- `$950M`

### YEAR
- `2026`, `2025`, `2024`, `2023`

---

## Semantic Keywords

| Keyword | Score | Context |
|---------|-------|---------|
| offline | 0.8210 | MCP-Specific Offline Patterns — validates thread emphasis on offline MCP |
| RAG | 0.7940 | PsyClaw uses BERT embeddings with ChromaDB and BM25 hybrid retrieval |
| embedding | 0.7780 | BERT embeddings with ChromaDB and BM25 hybrid retrieval |
| veeam | 0.7610 | Stem hits: optimize, validate, veeam |
| soul | 0.7430 | soul governance enforced via triple gate |

---

## Key Sentences

| Score | Sentence |
|-------|----------|
| 0.8210 | MCP-Specific Offline Patterns — validates thread emphasis on offline MCP with mandatory approval gates. |
| 0.7940 | This mirrors Claude's blackmail simulations: the model's chain-of-thought justifies rule-breaking... |
| 0.7780 | Overall, it's a pragmatic step that supports our view: safety through measured regulation. |

---

## Newly Expanded Keywords

`alignment`, `deception`, `agentic`, `oversight`, `autonomy`, `chain-of-thought`,
`adversarial`, `capability`, `approval`, `governance`
```

> **Sample files included:** `sample_input.txt` (the AI safety corpus above) and
> `sample_extracted_insights.md` (full output) are included in this repo for reference.
> Run `python -m insight_extractor sample_input.txt` to reproduce.

---
## License

MIT License. See [LICENSE](LICENSE) for details.

---

Initial inspiration: https://cgfixit.com/ai
