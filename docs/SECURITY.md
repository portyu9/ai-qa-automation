# Security

Security controls are enforced in code in addition to model instructions.

## Fail-closed runtime

The live runtime exposes the project-owned QA tool inventory rather than generic mutation/web tools. Unknown tools and unapproved MCP namespaces are denied. Approval-required actions fail closed during unattended execution.

## Filesystem

`PolicyEngine.authorize_path` resolves paths before policy checks, rejects target-workspace escape, protects governance/secret paths, and restricts optional writes to approved test directories.

## API and browser network boundaries

API access is host-allowlisted and read-only by default. API requests disable environment-proxy inheritance. Browser navigation, HTTP(S) subresources, and WebSocket connections are checked against the host allowlist; service workers are disabled and Chromium is launched without a proxy in the evidence context.

## Patch integrity

Safe patching combines optimistic-concurrency hashes, syntax validation, deterministic test-quality review, and explicit unsafe-diff patterns. Skips, xfails, arbitrary sleeps, timeout inflation, assertion removal, tautologies, and broad exception suppression are blocked.

## Performance

Production load testing is denied by policy. k6 targets must pass the runtime network allowlist. Scripts must use an injected target URL; bounded relative imports are recursively inspected; remote modules, `k6/x/*` extensions, local-file reads, and unrelated hard-coded external hosts are rejected; usage reporting is disabled; and runtime summary files are kept outside the SUT. Non-local execution also requires trusted configuration to assert infrastructure-level egress enforcement.

## MCP

External MCP must match the approved vendor identity. GitHub MCP runs read-only at the server layer, and tool policy independently separates read/write/destructive actions. Configuration alone is not treated as proof of remote availability.

## Secrets and artifacts

Evidence is sanitized recursively. Pytest output is redacted before it is returned or stored as a text artifact. Runtime pytest/k6/git subprocesses use credential-minimal environments and do not inherit the control process `PYTHONPATH`. Raw binary artifacts, such as screenshots, are labeled `RAW` rather than falsely marked sanitized and remain subject to artifact access/retention controls.

## Governance

Runtime policy files, Claude project settings/Skills/hooks, MCP configuration, and evaluation thresholds are protected from autonomous runtime mutation. Claude Code hooks also deny direct writes to their own hook directory and the GitHub workflow directory.

## Reporting a security issue

Do not place real credentials, private customer data, or exploit secrets in a public issue. Describe the smallest reproducible behavior without sensitive data.
