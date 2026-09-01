# Trusted Gate Service

External deployment source for the independent **Trusted PR Gate** admission service.

This package intentionally lives under the repository's protected `scripts/` root. Repository presence does not grant status authority. See [`docs/TRUSTED_PR_CONTROL_PLANE.md`](../../docs/TRUSTED_PR_CONTROL_PLANE.md) for the trust model, independent policy boundary, failure semantics, deployment contract, and activation sequence.

## Deployment adapters

The reviewed authority engine is shared by two deployment adapters:

- `python -m scripts.trusted_gate_service` is the host-neutral persistent HTTP reference adapter. It uses owner-controlled POSIX/Linux filesystem semantics and durable SQLite state.
- `scripts.trusted_gate_service.aws_lambda.handler` is the low-idle-cost AWS adapter. It uses a Lambda Function URL for ingress, SSM Parameter Store for deployment-owned configuration/secrets, and DynamoDB conditional/transactional writes for durable replay and publication state.

The AWS adapter does **not** rely on Lambda single-threading. A delivery has one atomic DynamoDB owner, duplicate concurrent invocations return retryable/busy truth, stale pre-publication ownership is recovered with a bounded attempt budget, and durable `PUBLISHING` state is never converted into an automatic second status POST.

## AWS authority boundary

The AWS deployment is intentionally outside candidate GitHub Actions and uses no VPC, NAT gateway, API Gateway, load balancer, EC2 instance, or container service. The intended deployment is Python 3.13 on Amazon Linux 2023 with a Lambda Function URL and a small DynamoDB table whose billing/capacity mode is independently observed.

Public source defines only the configuration interface. **Deployment values stay private in the AWS account and GitHub App settings.** Do not commit an AWS account ID, ARN, resource name, Function URL, SSM namespace, App installation identity, credential, webhook secret, one-shot policy, or deployment digest.

The Lambda environment provides only deployment-owned bindings:

- `TRUSTED_GATE_CONFIG_PREFIX`: private SSM namespace chosen by the deployment;
- `TRUSTED_GATE_TABLE_NAME`: exact deployment-owned DynamoDB state table;
- `TRUSTED_GATE_POLICY_SHA256`: independently pinned SHA-256 of the active one-shot policy.

Under the private SSM prefix, the adapter reads reviewed suffixes for App ID, bot login, installation ID, private key, repository identity, webhook secret, and the active one-shot policy. The concrete prefix and values are deliberately absent from repository source and tests. The adapter enforces the 4 KiB SSM **Standard-tier** value bound so this deployment contract does not silently require paid Advanced parameters.

The webhook HMAC is checked before private App authority configuration, the policy, or GitHub evidence is read. Missing, malformed, stale, mismatched, concurrent, infrastructure-failed, or unverifiable state never becomes `SUCCESS`.

For dependency/revision control, deployment evidence must record the exact source revision, deployment ZIP SHA-256, Lambda code SHA-256, and Lambda runtime version ARN. After a smoke invocation establishes the actual runtime version, runtime-management changes must be explicit maintenance events rather than silent changes beneath authority-bearing code.

## POSIX signing invariant

The shared GitHub App token provider requires a POSIX/Linux runtime with an addressable inherited-descriptor namespace and an absolute OpenSSL executable. It prefers `/proc/self/fd/<n>` (the path proven on AWS Lambda Python 3.13 / Amazon Linux 2023) and permits `/dev/fd/<n>` only as an explicitly checked compatibility fallback. GitHub App JWT signing passes the bounded ASCII private key through that anonymous/unlinked descriptor; it never creates a named PEM file that can remain after abrupt process termination. Activation requires real runtime proof of the selected descriptor namespace.

The persistent reference service exposes `GET /healthz` and `POST /github/webhook`. The Lambda adapter accepts only `POST /github/webhook`. TLS, GitHub webhook configuration, AWS account controls, one-shot policy administration, and the dedicated GitHub App credentials remain deployment-owned and must not be placed in candidate GitHub Actions.
