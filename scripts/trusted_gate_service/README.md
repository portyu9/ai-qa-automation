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

Under the private SSM prefix, the adapter reads reviewed suffixes for App ID, bot login, installation ID, signing credential, repository identity, webhook secret, and the active one-shot policy. The concrete prefix and values are deliberately absent from repository source and tests. The adapter enforces the 4 KiB SSM **Standard-tier** plaintext value bound so this deployment contract does not silently require paid Advanced parameters.

The webhook HMAC is checked before one-shot policy admission, private App signing authority, DynamoDB acquisition, or GitHub evidence access. Missing, malformed, stale, mismatched, concurrent, infrastructure-failed, or unverifiable state never becomes `SUCCESS`.

### KMS-decrypt minimization without authority reduction

The Lambda adapter deliberately separates cheap rejection and non-secret configuration from the two `SecureString` values that require plaintext access:

1. Function URL shape, GitHub Hookshot sender shape, exact `workflow_run` event header, delivery-header bounds, and `sha256=<64 lowercase hex>` signature shape are reject-only checks performed before any SSM read. They never establish authentication.
2. The webhook secret remains the first cryptographic authority. For a syntactically admissible request, the adapter reads the `SecureString` without decryption and binds the warm-cache candidate to both its exact SSM `Version` and a SHA-256 fingerprint of the returned encrypted value. A bounded warm cache may reuse the already decrypted secret only while both identities are unchanged, the cache is younger than five minutes, and fewer than 1024 bounded secret uses have occurred. A cache miss, identity change, age expiry, or use exhaustion requires one fresh decrypt. That decrypt is bracketed by non-decrypt reads: the decrypted response must retain the observed version and the post-decrypt encrypted-value fingerprint must still match the pre-decrypt observation. A rotation, delete/recreate collision, or replacement race therefore fails closed instead of blessing stale plaintext.
3. A valid HMAC is required before the deployment policy pin is consulted for admission. An all-zero policy pin is a deterministic idle state and returns `BLOCKED` without reading the policy parameter, App configuration/signing credential, DynamoDB, or GitHub.
4. An active one-shot policy is a non-secret `String` parameter and is read with `WithDecryption=False`; its bytes must match the deployment SHA-256 pin and parse as the exact reviewed policy schema.
5. The authenticated workflow wake-up is parsed and compared with the active policy's reviewed repository identity, activation interval, and exact head SHA before private App authority is read. `TrustedGateService` repeats the policy-head rejection before durable delivery acquisition.
6. App/repository identity values are non-secret `String` parameters and are read without decryption. The GitHub App signing credential remains a `SecureString` and is decrypted only after HMAC, active-policy, wake-up, and installation admission. That signing credential is intentionally **not** cached across warm invocations.

This optimization reduces recurring **KMS Decrypt** pressure; it does not claim zero SSM requests. A syntactically admissible request still performs a non-decrypt webhook-secret observation so secret rotation or replacement is detected instead of trusting a stale warm value. Cache refresh performs additional non-decrypt observations to bracket the single decrypt. The second HMAC check inside `TrustedGateService`, repeated live GitHub subject resolution, exact CI evidence checks, one-shot policy admission, durable publication recovery, and App-origin status validation remain unchanged authority controls.

For dependency/revision control, deployment evidence must record the exact source revision, deployment ZIP SHA-256, Lambda code SHA-256, and Lambda runtime version ARN. After a smoke invocation establishes the actual runtime version, runtime-management changes must be explicit maintenance events rather than silent changes beneath authority-bearing code.

## POSIX signing invariant

The shared GitHub App token provider requires a POSIX/Linux runtime with an addressable inherited-descriptor namespace and an absolute OpenSSL executable. It prefers `/proc/self/fd/<n>` (the path proven on AWS Lambda Python 3.13 / Amazon Linux 2023) and permits `/dev/fd/<n>` only as an explicitly checked compatibility fallback. GitHub App JWT signing passes the bounded ASCII signing material through that anonymous/unlinked descriptor; it never creates a named PEM file that can remain after abrupt process termination. Activation requires real runtime proof of the selected descriptor namespace.

The persistent reference service exposes `GET /healthz` and `POST /github/webhook`. The Lambda adapter accepts only `POST /github/webhook`. TLS, GitHub webhook configuration, AWS account controls, one-shot policy administration, and the dedicated GitHub App credentials remain deployment-owned and must not be placed in candidate GitHub Actions.
