# Reference SUT

This is a deliberately small FastAPI application used by deterministic integration tests and local agent scenarios.

Controlled modes include:

- normal checkout behavior
- application defect
- API failure
- timing delay
- prompt-injection-shaped DOM content

The application is test data for the agent architecture; it is not part of the trusted control plane.
