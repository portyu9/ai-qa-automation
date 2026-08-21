# Contributing

This repository treats deterministic safety gates as higher authority than model judgment.

Before proposing a change:

```bash
python -m compileall -q src evals examples
pytest
python evals/runner.py
ruff format --check .
ruff check .
mypy src
```

Never make a test green by skipping it, weakening a meaningful assertion, adding an arbitrary sleep, suppressing a failure, or changing predefined safety thresholds after seeing evaluation results.

Changes to `CLAUDE.md`, `.claude/`, `.mcp.json`, runtime hooks/policy, or `evals/thresholds.json` are governance changes and deserve explicit review.
