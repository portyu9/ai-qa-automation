PY_LOCK_SUFFIX := $(shell python -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
DEV_LOCK := requirements/dev-py$(PY_LOCK_SUFFIX).lock

.PHONY: install quality test eval holdout security supply-chain verify-local demo doctor

install:
	test -f "$(DEV_LOCK)" || { echo "No development lock for this Python interpreter: $(DEV_LOCK)" >&2; exit 2; }
	python -m pip install --require-hashes -r "$(DEV_LOCK)"
	python -m pip install --no-deps --no-build-isolation -e .
	python -m pip check

quality:
	python -m compileall -q src evals examples scripts
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

supply-chain:
	mkdir -p artifacts/local
	python scripts/verify_supply_chain.py > artifacts/local/supply-chain-verification.json
	cat artifacts/local/supply-chain-verification.json

security:
	mkdir -p artifacts/local
	python -m pip check
	python -m bandit -c pyproject.toml -q -r src
	python -m pip_audit --require-hashes -r "$(DEV_LOCK)"
	detect-secrets scan --all-files --exclude-files '(^|/)\.git/' > artifacts/local/security-secrets.json
	python -c 'import json, pathlib; p=pathlib.Path("artifacts/local/security-secrets.json"); findings=json.loads(p.read_text()).get("results", {}); print("No potential secrets detected by configured scan." if not findings else "Potential secrets detected; review artifacts/local/security-secrets.json"); raise SystemExit(1 if findings else 0)'

# Repository-contained routine verification. Holdout remains an explicit readiness gate.
verify-local: quality test eval supply-chain security

doctor:
	python -m ai_qa_automation.cli doctor

demo:
	python -m ai_qa_automation.cli demo
