.PHONY: install quality test eval demo doctor

install:
	python -m pip install -e '.[dev]'

quality:
	python -m ruff format --check src tests examples evals
	python -m ruff check src tests examples evals
	python -m mypy src
	python -m pytest

security:
	python -m bandit -c pyproject.toml -r src

test:
	python -m pytest

eval:
	python evals/runner.py

doctor:
	python -m ai_qa_automation.cli doctor

demo:
	python -m ai_qa_automation.cli demo
