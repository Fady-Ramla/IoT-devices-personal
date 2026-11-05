# SecureIoT Source-Only Review Snapshot

This branch is a source snapshot for review and cleanup, not a production-ready release.

## Source and layout

- Base source files were collected from the public `network-dashboard-contract` snapshot at commit `bb012145f5acafd627ddf4f1b9515633110f84d4`.
- Files from the uploaded `secureiot-integration-review.tar.gz` were overlaid at matching paths so the supplied VM versions take precedence.
- The snapshot is designed to be published as a new root/orphan branch. It does not inherit the base branch history or tree.
- It includes source code, selected integration configuration, and technical documentation only. Several legacy or experimental files are intentionally retained for review; their presence is not an approval to deploy them.

## Explicit exclusions

No CSV datasets, raw packet captures, model binaries, reports, local environment files, credentials, runtime databases, or other generated evaluation artifacts belong in this snapshot. The sealed 160-run final holdout is excluded. Do not add the full working tree or use `git add .` from the original VM repository.

## Important status

This is an upload/review snapshot. It is not the cleaned production branch yet. The review identified required fixes to the Ryu/Flask bridge, telemetry token propagation and payload shape, route authentication, duplicate controller sources, path defaults, and the shadow-model contract. See the separately prepared `SecureIoT_Source_Code_Review_2026-11-05.md` before treating any file as authoritative.

## Suggested use

Publish this source-only snapshot on a separate branch such as `secureiot-source-review` so the project code can be reviewed without inheriting data artifacts or unrelated branch history. After review and fixes, create a separate clean integration release branch with only the canonical implementation and passing tests.
