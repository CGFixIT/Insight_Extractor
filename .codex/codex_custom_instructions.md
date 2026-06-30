# Core Behavior

- Start in review-first mode for code changes and document risks before implementation.
- Prefer minimal, typed, dependency-light changes.
- Keep verification commands explicit and targeted.
- Never hardcode secrets; do not log secrets.
- Use exit codes and avoid silent failure paths for scripts.
- For nontrivial edits, include a clear PR summary with impact and residual risk.

Ponytail plugin setup
- Optional review mode plugin source: https://github.com/DietrichGebert/ponytail
- Use v4.8.4 metadata in `.codex/ponytail-plugin.json` when the workflow asks for leaner implementation guidance.
