# Security Policy

This public portfolio repository contains no intended secrets. Never commit credentials, private customer data, or production artifacts.

The runtime is designed around least privilege, target/control-plane separation, secret redaction, official-MCP allowlisting, path confinement, deterministic policy hooks, and explicit `NOT_VERIFIED` states.

If you discover a security weakness, do not demonstrate it using real credentials or sensitive data in a public issue. Describe the minimal reproducible behavior without secrets.
