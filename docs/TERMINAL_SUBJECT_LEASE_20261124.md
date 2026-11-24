# Terminal exact-subject lease (2026-11-24)

Issue: #464. Accepted lineage before this branch: 8da389b604a860997d88e52cb7ae7c72d2b9bf54. Closed historical fix branches are strictly behind main. Closed divergent generated promotion #470 is superseded by accepted #472; original signed source #468 was not rewritten.

## Failure reproduced
A newly eligible higher-priority owner-protected PR can appear while full trusted validation executes. Terminal global queue reselection then chooses the new subject and rejects the initially qualified PR, wasting the validation and blocking unattended liveness. The original terminal mismatch check correctly fails closed; do not remove it.

## Change
The initial trusted-main preflight still applies global priority. Reporter revalidation instead receives immutable original lane/PR/head/base/merge/current-main identities from initial preflight; re-fetches the authenticated native wake and original PR and exact Git merge/tree evidence; scopes discovery to the original PR; and checks every original field and eligibility before creating an App token. The existing owner comment proof, generated promotion check, bot signature/qualification, and per-lane trusted follow-up controls are retained. Unrelated new PRs cannot change the selected terminal subject. Changes to the *original* subject, main, or wake remain terminal failures. All credentials remain in the reporter environment; read-only revalidation precedes App token creation.

## Non-goals
No review bypass, broadened bot lane, new credential scope, automatic security-alert closure, or guaranteed GitHub schedule delivery. Full qualification and live post-merge evidence are required before issue #464 closure.
