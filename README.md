# boundary-drift-detector

[![CI](https://github.com/JulietRodriguez/boundary-drift-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/JulietRodriguez/boundary-drift-detector/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Compares a system's **declared authorization boundary** (the SSP's inventory, or a short YAML file)
with **what actually exists** in AWS (an AWS Config inventory, Terraform state, or a live AWS Config
query). It reports resources that are undeclared, missing, in the wrong region, unencrypted, or
publicly exposed, as Markdown, JSON and OSCAL, and it can block a CI pipeline.

It covers the **Prepare** step of the NIST SP 800-37 Risk Management Framework (task P-11, the
authorization boundary), and it keeps that boundary honest during monitoring (CM-8, System
Component Inventory).

## The problem

The SSP's inventory is approved once. The cloud account changes every day. A bucket someone created
for a "quick export" was never assessed and isn't in the SSP. A server that was decommissioned is
still listed. Nobody notices until an assessor compares the two by hand, months later.

## What it checks

| Drift | Severity | Control |
|---|---|---|
| **Undeclared**: exists, but isn't in the boundary | high, or critical if it's publicly exposed | CM-8 |
| **Missing**: declared, but not found | medium | CM-8 |
| **Region**: in a different region than declared, or outside the boundary's regions | high | CM-8 |
| **Encryption**: expected encrypted at rest, found unencrypted | high | SC-28 |
| **Public**: expected private, found publicly exposed | critical | SC-7 |
| **Unverified**: an expectation the inventory can't confirm either way | info | (none) |

Resources are matched by ARN first, then by type plus ID, then by type plus name. Unknown values are
reported as *unverified*, never guessed. IAM and other global resources are never flagged for region,
and AWS Config's own compliance records are ignored as non-assets. Terraform settings resources that some SSP
generators list as inventory items (for example `aws_s3_bucket_server_side_encryption_configuration`)
are skipped and counted, since they configure an asset rather than being one.

## Quick start

```bash
pip install -e .                 # PyYAML only
pip install -e ".[aws]"          # adds boto3 for live mode

boundary-drift-detector check \
  --declared samples/ssp.json \
  --actual samples/aws-config-export.json \
  -o out --fail-on high
```

```
SYNTHETIC Case Management System (CMS-DEMO): 5 drift finding(s) (critical 2, high 2, medium 1, low 0); 8/9 declared resources matched, 10 in the inventory
  CRITICAL undeclared AWS::S3::Bucket arn:aws:s3:::cms-demo-export-tmp: Exists in the inventory but is not declared in the boundary (in region us-west-2, outside the boundary's regions), and it is publicly exposed.
  CRITICAL public     AWS::EC2::SecurityGroup arn:aws:ec2:us-east-1:111122223333:security-group/sg-0a1b2c3d4e5f60001: Expected private; found publicly exposed.
  HIGH     undeclared AWS::EC2::Instance arn:aws:ec2:us-east-1:111122223333:instance/i-0a1b2c3d4e5f69999: Exists in the inventory but is not declared in the boundary.
  HIGH     encryption AWS::RDS::DBInstance arn:aws:rds:us-east-1:111122223333:db:cms-demo-db: Expected encrypted at rest; found unencrypted.
gate: drift at or above 'high'
```

Exit codes: `0` no drift at or above `--fail-on`, `1` drift at or above it, `2` bad input.

### Inputs

**Declared boundary** (`--declared`):

- an **OSCAL SSP** (JSON): each `inventory-items` entry, using the props `asset-id` (ARN or ID),
  `resource-type`, `region`, and optionally `public` / `encrypted` (yes/no). These are the props
  [oscal-ssp-generator](https://github.com/JulietRodriguez/oscal-ssp-generator) writes.
- or a **YAML** file:

```yaml
boundary:
  name: CMS-DEMO production
  accounts: ["111122223333"]
  regions: [us-east-1]
  expect: {encrypted: true, public: false}     # applies to the types where these can be read
resources:
  - id: arn:aws:s3:::cms-demo-case-files
    type: AWS::S3::Bucket
  - id: arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/cms-demo-alb/0a1b2c3d4e5f6001
    type: AWS::ElasticLoadBalancingV2::LoadBalancer
    public: true                                # internet-facing by design
```

**What actually exists** (`--actual`, repeatable, or `--aws`):

- AWS Config: `aws configservice select-resource-config` (or the aggregate version), `batch-get-resource-config`,
  a Config snapshot file, or a JSON list of configuration items
- Terraform state (`terraform.tfstate` v4, or `terraform show -json`); helper resources such as
  `aws_s3_bucket_public_access_block` are folded into the bucket they configure
- `--aws` reads AWS Config live with one read-only query (`config:SelectResourceConfig`, or
  `config:SelectAggregateResourceConfig` with `--aggregator`). Options: `--aws-region`, `--aws-profile`

Rules can also be set on the command line: `--region`, `--account`, `--expect-encrypted`, `--expect-public`.

## Outputs

| File | What it is |
|---|---|
| `drift-report.md` / `.json` | Counts, boundary regions and accounts, match methods, every drift with its control, and what to do |
| `drift.oscal.json` | OSCAL 1.1.2 Assessment Results: one observation per drift, subjects pointing at the SSP's inventory-items (undeclared resources are defined in the result), and one not-satisfied finding per control with the worst severity |

The OSCAL output is validated against NIST's official 1.1.2 schema in CI, and
[ato-readiness-checker](https://github.com/JulietRodriguez/ato-readiness-checker) reads it as Assessment Results.

## Samples (all synthetic)

Built by [`tools/make_samples.py`](tools/make_samples.py). Account `111122223333` is AWS's documentation example.

| Comparison | Result |
|---|---|
| `samples/ssp.json` vs `samples/aws-config-export.json` | 5 drift findings: an undeclared public bucket in another region (critical), a security group open to the internet (critical), an undeclared instance (high), an unencrypted database (high), a missing instance (medium), plus 1 unverified |
| `samples/boundary.yaml` vs `samples/aws-config-export.json` | The same drift, from the YAML boundary |
| `samples/boundary.yaml` vs `samples/terraform.tfstate` | No drift: 9 of 9 resources matched by ARN |

Outputs for each are in [samples/outputs](samples/outputs).

## Design choices (short version)

Plain-language explanations are in [docs/design-notes.md](docs/design-notes.md).

- **Match on ARN first;** show how each match was made.
- **Unknown stays unknown:** an expectation the inventory can't confirm is reported as unverified, not passed or failed.
- **Severity follows risk:** public exposure is critical; a missing resource is usually documentation lag.
- **Works with what teams have:** an OSCAL SSP or YAML; AWS Config or Terraform; files or live.
- **OSCAL output** feeds the authorization package review, with subjects that resolve to the SSP's own inventory.

## Limits

- AWS only. Encryption and exposure are read for the common types listed in the design notes; other
  types are compared for presence and region only.
- "Public" is a signal, not proof of exposure (a public IP behind a closed security group isn't reachable).
- Live mode needs AWS Config to be recording in the account (or an aggregator for many accounts), and
  sees only what Config records.
- It compares inventories; it doesn't check whether data flows or interconnections match the SSP.
- Synthetic sample data only. Live mode is tested with a fake AWS client, not against a real account.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=boundary_drift_detector
ruff check . && ruff format --check .
python tools/make_samples.py --check
```

CI runs lint, tests on Python 3.10–3.14, a samples drift check, and an OSCAL job that downloads NIST's
v1.1.2 schemas, verifies their SHA-256, validates the sample SSP and every drift output, and checks
that the gate blocks the drifted inventory and passes the clean one.

## License

[Apache-2.0](LICENSE). Copyright 2026 Juliet Rodriguez.
