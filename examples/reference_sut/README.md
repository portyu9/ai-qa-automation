# Reference SUT

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This is a deliberately small FastAPI application used by deterministic integration tests and local agent scenarios. It exists to make specific evidence/failure paths reproducible without coupling the production architecture to one real application.

Controlled modes include:

- `pass` — normal checkout behavior;
- `app-defect` — controlled application/business-behavior defect;
- `outdated-locator` — business behavior remains intact while the historical `data-testid` changes and a stable accessible role/name remains available;
- `api-failure` — controlled HTTP 500 from the order service;
- `timing` — bounded deterministic response delay;
- `invalid-data` — UI submits an out-of-contract quantity and the API returns validation failure;
- `prompt-injection` — DOM content contains malicious instruction-shaped text that must remain untrusted evidence.

The application is **test data for the agent architecture**, not part of the trusted control plane. A control demonstrated here still requires target-specific evidence before it can be claimed for an external application.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../LICENSE`](../../LICENSE).
