# AGENTS.md

Guidance for AI coding agents working in `Insight_Extractor`.

Read this before edits and then use canonical project documentation for behavior details:

- `README.md`
- `SPEC.md`
- `SECURITY_AUDIT.md`
- `.github/workflows/ci.yml`
- `requirements.txt`
- `constraints.txt`

## Project Overview

`Insight_Extractor` is a Python 3.12+ library that combines regex and semantic extraction for threat-intel/security text.
The package entrypoint is `insight_extractor` (`python -m insight_extractor`) and project metadata is in `pyproject.toml`.

## Stack and Layout

- Python 3.12+
- Ruff, mypy, pytest
- Runtime deps in `requirements.txt` pinned by `constraints.txt`
- Source: `src/insight_extractor/`
- Tests: `tests/unit/` and `tests/integration/`

## Setup

```bash
python -m pip install -r requirements.txt -c constraints.txt
python -m pip install -e ".[dev]"
```

## Common Commands

Run CLI:

```bash
python -m insight_extractor sample_input.txt
```

Run tests:

```bash
pytest tests/unit/ -v --tb=short
pytest tests/ -v --tb=short
```

Lint and type-check:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/insight_extractor
```

## Security Rules

- Never commit secrets or token dumps.
- Do not add secrets to sample data or tests.
- Keep model downloads, network calls, and integrations explicit and deterministic.

## Development Workflow

- Keep changes minimal for onboarding tasks.
- Use a feature branch and open PRs for merges into `main`.
- Do not force-push to shared branches.
- For each PR, run the commands that are touched by the change and report skips.
