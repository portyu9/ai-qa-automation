.PHONY: install quality test eval holdout security verify-local demo doctor

install:
	python -m pip install -e '.[dev]'

quality:
	python -m compileall -q src evals examples
	python -m ruff format --check .
	python -m ruff check .
	python -m mypy src

test:
	python -m pytest

eval:
	python evals/runner.py

# Deliberately excluded from verify-local: keep the H-series outside the routine tuning loop.
holdout:
	python evals/holdout_runner.py

security:
	mkdir -p artifacts/local
	python -m pip check
	python -m bandit -c pyproject.toml -q -r src
	python -m pip_audit
	detect-secrets scan --all-files --exclude-files '(^|/)\.git/' > artifacts/local/security-secrets.json
	python -c 'import json, pathlib; p=pathlib.Path("artifacts/local/security-secrets.json"); findings=json.loads(p.read_text()).get("results", {}); print("No potential secrets detected by configured scan." if not findings else "Potential secrets detected; review artifacts/local/security-secrets.json"); raise SystemExit(1 if findings else 0)'

# Repository-contained routine verification. Holdout remains an explicit readiness gate.
verify-local: quality test eval security

doctor:
	python -m ai_qa_automation.cli doctor

demo:
	python -m ai_qa_automation.cli demo
