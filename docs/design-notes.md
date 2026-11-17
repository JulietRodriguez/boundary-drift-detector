# Design notes

Why boundary-drift-detector works the way it does, in plain language.

## 1. The problem it solves

**Choice:** Compare two lists: what the SSP says is inside the authorization boundary, and what
actually exists in the AWS account. Report every difference.

**Why:** The authorization boundary is defined in the RMF Prepare step (SP 800-37 Rev. 2, task P-11)
and then documented in the SSP. In the cloud, people create resources in minutes, so the SSP is out
of date almost as soon as it's approved. An undeclared resource was never assessed. A declared one that's
gone means the SSP is wrong. Both undercut the authorization. CM-8 (System Component Inventory)
expects the inventory to match reality; this tool checks that it does.

## 2. Two ways to declare the boundary

**Choice:** Read the declared boundary from an OSCAL SSP's `inventory-items`, or from a short YAML file.

**Why:** Teams with an OSCAL SSP shouldn't keep a second list. The props the tool reads (`asset-id`,
`resource-type`, `region`) are the ones oscal-ssp-generator writes, and a test proves an SSP from that
tool round-trips with zero drift. Teams without an OSCAL SSP can still start with YAML, and YAML is
also where boundary-wide rules (`regions`, `accounts`, `expect`) are easiest to write.

## 3. Three ways to see what actually exists

**Choice:** AWS Config exports (four formats the AWS CLI writes), Terraform state, or a live
read-only AWS Config query with boto3.

**Why:** AWS Config records what is actually there, including things created by hand. Terraform
state shows what the code manages, so comparing it to the SSP catches documentation drift before
anything is deployed. The live mode uses one advanced query (`select_resource_config`, or the
aggregator version for many accounts) so it needs just one read-only permission. The AWS client is
passed in, so the tests use a fake one and need no AWS account.

## 4. Match on ARN first

**Choice:** Match declared to actual by ARN, then by resource type plus ID, then by type plus name.
The report counts how each match was made.

**Why:** An ARN is unique, so ARN matches are certain. The fallbacks exist for hand-written YAML
that lists a bucket by name or an IAM role by name (AWS Config uses an opaque ID for roles). Showing
the match method lets a reviewer see when the weaker matches were used. When two resources share a
name, the one in the declared region wins.

## 5. Five kinds of drift, with severities that reflect risk

| Kind | Severity | Why that severity |
|---|---|---|
| undeclared | high (critical if public) | Never assessed; if it's public, it may already be exposing data |
| missing | medium | Usually a documentation lag, but the SSP is wrong |
| region | high | Data may be stored where it isn't authorized to be |
| encryption | high | SC-28 expectation broken |
| public | critical | Something meant to be private is reachable from the internet |

The `--fail-on` gate uses these, so a pipeline can block on critical only, or on anything.

## 6. Unknown stays unknown

**Choice:** Encryption and public exposure are True or False only when the source states them;
otherwise they're None. An expectation that can't be checked is reported as **unverified** (info),
never as a pass and never as drift. Unverified items don't produce OSCAL findings.

**Why:** AWS Config doesn't record every setting for every resource (an S3 bucket's encryption
setting may be missing from an export). Guessing "encrypted" would hide a real gap; guessing
"unencrypted" would create false alarms people learn to ignore. Saying "couldn't verify" is honest
and tells the reviewer where to look.

## 7. Boundary-wide rules apply only where they make sense

**Choice:** `expect: {encrypted: true, public: false}` applies to the resource types where those
properties exist and can be read (S3, EBS, RDS, DynamoDB, EFS for encryption; S3, EC2, RDS, load
balancers, security groups, DynamoDB for exposure). A rule written on one resource always applies.

**Why:** "Every KMS key must not be public" isn't a meaningful check, and applying it would flood
the report with unverified items. Keeping the lists explicit makes the behavior predictable.

## 8. How "public" is decided

- **S3:** private if all four Block Public Access settings are on; public if an ACL grants
  AllUsers/AuthenticatedUsers or the bucket policy allows `Principal: "*"` with no condition.
- **EC2 instance:** public if it has a public IP.
- **RDS:** the `publiclyAccessible` setting.
- **Load balancer:** `internet-facing` scheme.
- **Security group:** any inbound rule from 0.0.0.0/0 or ::/0.

These are signals, not proof of a data exposure: a public IP behind a locked-down security group
isn't reachable. The point is to flag a difference from what the SSP declared, for a person to review.

## 9. Global resources and not-an-asset types

**Choice:** Resources AWS Config reports in region `global` (IAM) are never region drift. Config's
own records that aren't system assets (compliance results, backup recovery points) are ignored by
default and counted in the report, unless the boundary declares that type.

**Why:** Both rules came out of testing the sample. Without them, every IAM role showed up as region
drift and every compliance record as an undeclared resource. That noise hides the real findings.

## 10. OSCAL output that plugs into the next step

**Choice:** Write Assessment Results. Each drift is an observation whose subject is the SSP's own
inventory-item (or, for undeclared resources, an inventory-item defined in the result). Drifts are
grouped into one not-satisfied finding per control (CM-8, SC-28, SC-7) with the worst severity as a
prop. No "satisfied" findings are written.

**Why:** ato-readiness-checker reads Assessment Results, so a drift check can go straight into the
authorization package review. Pointing subjects at the SSP's inventory-items means the references
resolve across the package. A clean drift check shows the inventory matches the boundary; it doesn't
prove CM-8 or SC-7 are fully implemented, so the tool doesn't claim they are.

## 11. Deterministic and testable

**Choice:** UUIDv5 identifiers, a fixed timestamp for the committed samples, synthetic data built by
`tools/make_samples.py`, and a CI job that fails if the samples drift from the script.

**Why:** Same inputs, same outputs, on any machine. The samples double as documentation: one AWS
Config export with every kind of drift, and one Terraform state that matches the boundary exactly.
