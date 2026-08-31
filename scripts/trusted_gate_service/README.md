# Trusted Gate Service

Host-neutral reference/deployment source for the external **Trusted PR Gate** admission service.

This package intentionally lives under the repository's protected `scripts/` root. Repository presence does not grant status authority. See [`docs/TRUSTED_PR_CONTROL_PLANE.md`](../../docs/TRUSTED_PR_CONTROL_PLANE.md) for the trust model, independent policy boundary, failure semantics, deployment contract, and activation sequence.

Run the HTTP entrypoint only in an independently administered deployment:

```bash
python -m scripts.trusted_gate_service
```

The service exposes `GET /healthz` and `POST /github/webhook`. Its secrets, policy, durable SQLite state, TLS/ingress controls, and dedicated GitHub App credentials are deployment-owned and must not be placed in this repository or candidate GitHub Actions.
