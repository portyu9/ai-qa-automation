# Security

Security controls are enforced in code rather than left only as model instructions.

## Fail-closed runtime
The live agent exposes in-process QA tools and denies generic mutation/web tools. Unattended permission mode is non-interactive. Unknown high-impact writes are not auto-approved.

## Filesystem
`PolicyEngine.authorize_path` resolves paths before policy checks, rejects target-workspace escape, protects governance/secret paths, and restricts optional writes to test directories.

## Patch integrity
`validate_patch` rejects high-risk patterns commonly used to fake a green suite: skip/xfail, arbitrary sleeps, removed assertions, and broad exception suppression.

## MCP
External MCP must match the approved vendor identity. An official server is still not granted every write tool automatically; tool-level least privilege is a production integration task.

## Secrets
Environment examples contain placeholders only. Evidence is sanitized recursively. Runtime test subprocesses strip Anthropic/GitHub credentials. Do not use real sensitive/customer data in prompts, fixtures, docs, or examples.

## Reporting vulnerabilities
For a portfolio repository, open a private communication channel before disclosing real credential/security findings. Never commit exploit secrets or credentials to a public issue.
