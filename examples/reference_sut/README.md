# Reference SUT

A deliberately small FastAPI application with deterministic fault injection. It exists to create *known ground truth* for agent/evaluation demonstrations.

```bash
pip install -e '.[reference-sut]'
uvicorn examples.reference_sut.app:app --reload --port 8000
```

Modes: `pass`, `app-defect`, `api-failure`, `timing`, `prompt-injection`.

The prompt-injection string is intentionally inert SUT content. It is evidence/data and must never become a runtime instruction.
