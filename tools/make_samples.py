"""Build the synthetic samples in samples/ and their outputs.

    python tools/make_samples.py            # write
    python tools/make_samples.py --check    # exit 1 if committed files differ

Everything is SYNTHETIC: invented account 111122223333 (AWS's documentation
account number), invented resource names. No real system data.

samples/boundary.yaml           the declared boundary, as YAML
samples/ssp.json                the same boundary as an OSCAL SSP inventory
samples/aws-config-export.json  an AWS Config select-resource-config export WITH drift
samples/terraform.tfstate       Terraform state that matches the boundary (no drift)
samples/outputs/                what the tool writes for each comparison
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
TIMESTAMP = "2026-11-17T12:00:00+00:00"
ACCOUNT = "111122223333"
REGION = "us-east-1"
NS = uuid.UUID("0f6b2c1e-2d7a-5b9c-8e4f-1a2b3c4d5e6f")


def uid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "|".join(parts)))


def arn(service: str, resource: str, region: str = REGION) -> str:
    return f"arn:aws:{service}:{region}:{ACCOUNT}:{resource}"


# The declared boundary: (type, id, arn, name, extra expectations)
DECLARED = [
    ("AWS::S3::Bucket", "cms-demo-case-files", "arn:aws:s3:::cms-demo-case-files", None),
    ("AWS::S3::Bucket", "cms-demo-logs", "arn:aws:s3:::cms-demo-logs", None),
    ("AWS::EC2::Instance", "i-0a1b2c3d4e5f60001", arn("ec2", "instance/i-0a1b2c3d4e5f60001"), "cms-demo-web-1"),
    ("AWS::EC2::Instance", "i-0a1b2c3d4e5f60002", arn("ec2", "instance/i-0a1b2c3d4e5f60002"), "cms-demo-web-2"),
    ("AWS::EC2::SecurityGroup", "sg-0a1b2c3d4e5f60001", arn("ec2", "security-group/sg-0a1b2c3d4e5f60001"), "cms-demo-app"),
    ("AWS::RDS::DBInstance", "db-CMSDEMOEXAMPLE0001", arn("rds", "db:cms-demo-db"), "cms-demo-db"),
    ("AWS::ElasticLoadBalancingV2::LoadBalancer", "cms-demo-alb",
     arn("elasticloadbalancing", "loadbalancer/app/cms-demo-alb/0a1b2c3d4e5f6001"), "cms-demo-alb"),
    ("AWS::KMS::Key", "0a1b2c3d-0000-4000-8000-000000000001", arn("kms", "key/0a1b2c3d-0000-4000-8000-000000000001"), None),
    ("AWS::IAM::Role", "AROAEXAMPLEROLE000001", f"arn:aws:iam::{ACCOUNT}:role/cms-demo-app", "cms-demo-app"),
]  # fmt: skip
# The load balancer is the system's front door, so the boundary says it is public.
DECLARED_PUBLIC = {"cms-demo-alb"}


def boundary_yaml() -> str:
    lines = [
        "# SYNTHETIC boundary for an invented system. Account 111122223333 is AWS's documentation example.",
        "boundary:",
        "  name: SYNTHETIC Case Management System (CMS-DEMO) production",
        f'  accounts: ["{ACCOUNT}"]',
        f"  regions: [{REGION}]",
        "  expect:",
        "    encrypted: true     # every storage resource must be encrypted at rest",
        "    public: false       # nothing is public unless a resource says so",
        "resources:",
    ]
    for rtype, _rid, a, name in DECLARED:
        lines.append(f"  - id: {a}")
        lines.append(f"    type: {rtype}")
        if name:
            lines.append(f"    name: {name}")
        if (name or "") in DECLARED_PUBLIC:
            lines.append("    public: true        # internet-facing by design")
    return "\n".join(lines) + "\n"


def ssp() -> dict:
    items = []
    for rtype, _rid, a, name in DECLARED:
        props = [
            {"name": "asset-id", "value": a},
            {"name": "resource-type", "value": rtype},
        ]
        if not a.startswith("arn:aws:s3") and not a.startswith("arn:aws:iam"):
            props.append({"name": "region", "value": REGION})
        if name:
            props.append({"name": "asset-name", "value": name})
        if rtype not in (
            "AWS::KMS::Key",
            "AWS::IAM::Role",
        ):  # exposure isn't a property of these
            props.append(
                {
                    "name": "public",
                    "value": "yes" if (name or "") in DECLARED_PUBLIC else "no",
                }
            )
        if rtype in ("AWS::S3::Bucket", "AWS::RDS::DBInstance"):
            props.append({"name": "encrypted", "value": "yes"})
        items.append(
            {
                "uuid": uid("inv", a),
                "description": f"{rtype} {name or a}",
                "props": props,
                "implemented-components": [{"component-uuid": uid("component", "this-system")}],
            }
        )
    return {
        "system-security-plan": {
            "uuid": uid("ssp"),
            "metadata": {
                "title": "SYNTHETIC SSP inventory for CMS-DEMO",
                "last-modified": TIMESTAMP,
                "version": "1.0",
                "oscal-version": "1.1.2",
                "remarks": "SYNTHETIC sample for boundary-drift-detector. Not a real system.",
            },
            "import-profile": {"href": "#" + uid("profile")},
            "system-characteristics": {
                "system-ids": [
                    {
                        "identifier-type": "https://ietf.org/rfc/rfc4122",
                        "id": uid("system"),
                    }
                ],
                "system-name": "SYNTHETIC Case Management System (CMS-DEMO)",
                "description": "Synthetic system for the boundary drift sample.",
                "system-information": {
                    "information-types": [
                        {
                            "title": "Case records",
                            "description": "Synthetic information type.",
                        }
                    ]
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": f"AWS account {ACCOUNT}, region {REGION}: the resources in the inventory below."
                },
            },
            "system-implementation": {
                "users": [{"uuid": uid("user"), "title": "Caseworker"}],
                "components": [
                    {
                        "uuid": uid("component", "this-system"),
                        "type": "this-system",
                        "title": "CMS-DEMO",
                        "description": "The whole system.",
                        "status": {"state": "operational"},
                    }
                ],
                "inventory-items": items,
            },
            "control-implementation": {
                "description": "Not part of this sample.",
                "implemented-requirements": [{"uuid": uid("req"), "control-id": "cm-8"}],
            },
            "back-matter": {"resources": [{"uuid": uid("profile"), "title": "Baseline profile (not included)"}]},
        }
    }


def _ci(rtype, rid, a, name, configuration=None, supplementary=None, region=REGION):
    item = {
        "arn": a,
        "resourceType": rtype,
        "resourceId": rid,
        "awsRegion": region,
        "accountId": ACCOUNT,
        "configuration": configuration or {},
        "supplementaryConfiguration": supplementary or {},
    }
    if name:
        item["resourceName"] = name
    return item


PAB_ON = {
    "blockPublicAcls": True,
    "ignorePublicAcls": True,
    "blockPublicPolicy": True,
    "restrictPublicBuckets": True,
}
SSE = {"rules": [{"applyServerSideEncryptionByDefault": {"sseAlgorithm": "aws:kms"}}]}


def config_export() -> dict:
    """AWS Config inventory with deliberate drift (comments say which)."""
    items = [
        # matches, encrypted, private
        _ci("AWS::S3::Bucket", "cms-demo-case-files", "arn:aws:s3:::cms-demo-case-files", "cms-demo-case-files",
            supplementary={"PublicAccessBlockConfiguration": PAB_ON, "ServerSideEncryptionConfiguration": SSE}),
        # matches; Config recorded no encryption setting -> unverified (info)
        _ci("AWS::S3::Bucket", "cms-demo-logs", "arn:aws:s3:::cms-demo-logs", "cms-demo-logs",
            supplementary={"PublicAccessBlockConfiguration": PAB_ON}),
        # matches, no public IP
        _ci("AWS::EC2::Instance", "i-0a1b2c3d4e5f60001", arn("ec2", "instance/i-0a1b2c3d4e5f60001"), "cms-demo-web-1",
            configuration={"privateIpAddress": "10.0.1.10", "networkInterfaces": []}),
        # i-...0002 is MISSING (declared, not in the inventory)
        # declared private, but open to 0.0.0.0/0 -> PUBLIC drift (critical)
        _ci("AWS::EC2::SecurityGroup", "sg-0a1b2c3d4e5f60001", arn("ec2", "security-group/sg-0a1b2c3d4e5f60001"),
            "cms-demo-app", configuration={"ipPermissions": [
                {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipv4Ranges": [{"cidrIp": "0.0.0.0/0"}]}]}),
        # declared encrypted, storage not encrypted -> ENCRYPTION drift (high)
        _ci("AWS::RDS::DBInstance", "db-CMSDEMOEXAMPLE0001", arn("rds", "db:cms-demo-db"), "cms-demo-db",
            configuration={"storageEncrypted": False, "publiclyAccessible": False}),
        # declared public by design -> fine
        _ci("AWS::ElasticLoadBalancingV2::LoadBalancer", "cms-demo-alb",
            arn("elasticloadbalancing", "loadbalancer/app/cms-demo-alb/0a1b2c3d4e5f6001"), "cms-demo-alb",
            configuration={"scheme": "internet-facing"}),
        _ci("AWS::KMS::Key", "0a1b2c3d-0000-4000-8000-000000000001",
            arn("kms", "key/0a1b2c3d-0000-4000-8000-000000000001"), None),
        _ci("AWS::IAM::Role", "AROAEXAMPLEROLE000001", f"arn:aws:iam::{ACCOUNT}:role/cms-demo-app", "cms-demo-app",
            region="global"),
        # UNDECLARED, in another region, and public via its bucket policy -> critical
        _ci("AWS::S3::Bucket", "cms-demo-export-tmp", "arn:aws:s3:::cms-demo-export-tmp", "cms-demo-export-tmp",
            region="us-west-2", supplementary={"BucketPolicy": {"policyText": json.dumps({"Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::cms-demo-export-tmp/*"}]})}}),
        # UNDECLARED, private -> high
        _ci("AWS::EC2::Instance", "i-0a1b2c3d4e5f69999", arn("ec2", "instance/i-0a1b2c3d4e5f69999"), "debug-box",
            configuration={"privateIpAddress": "10.0.1.99", "networkInterfaces": []}),
        # not a system asset -> ignored by type
        _ci("AWS::Config::ResourceCompliance", "AWS::S3::Bucket/cms-demo-logs",
            arn("config", "resource-compliance/AWS::S3::Bucket/cms-demo-logs"), None),
    ]  # fmt: skip
    return {"Results": [json.dumps(i, separators=(",", ":")) for i in items]}


def terraform_state() -> dict:
    def res(tf_type, name, attrs):
        return {
            "mode": "managed",
            "type": tf_type,
            "name": name,
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [{"attributes": attrs}],
        }

    resources = []
    for bucket in ("cms-demo-case-files", "cms-demo-logs"):
        n = bucket.replace("-", "_")
        resources += [
            res("aws_s3_bucket", n, {"id": bucket, "bucket": bucket, "arn": f"arn:aws:s3:::{bucket}", "region": REGION}),
            res("aws_s3_bucket_public_access_block", n, {"bucket": bucket, "block_public_acls": True,
                "ignore_public_acls": True, "block_public_policy": True, "restrict_public_buckets": True}),
            res("aws_s3_bucket_server_side_encryption_configuration", n, {"bucket": bucket}),
        ]  # fmt: skip
    for i in ("1", "2"):
        rid = f"i-0a1b2c3d4e5f6000{i}"
        resources.append(res("aws_instance", f"web_{i}", {"id": rid, "arn": arn("ec2", f"instance/{rid}"),
                                                          "public_ip": "", "tags": {"Name": f"cms-demo-web-{i}"}}))  # fmt: skip
    resources += [
        res("aws_security_group", "app", {"id": "sg-0a1b2c3d4e5f60001", "name": "cms-demo-app",
            "arn": arn("ec2", "security-group/sg-0a1b2c3d4e5f60001"),
            "ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/16"]}]}),
        res("aws_db_instance", "db", {"id": "db-CMSDEMOEXAMPLE0001", "identifier": "cms-demo-db",
            "arn": arn("rds", "db:cms-demo-db"), "storage_encrypted": True, "publicly_accessible": False}),
        res("aws_lb", "alb", {"id": arn("elasticloadbalancing", "loadbalancer/app/cms-demo-alb/0a1b2c3d4e5f6001"),
            "name": "cms-demo-alb", "internal": False,
            "arn": arn("elasticloadbalancing", "loadbalancer/app/cms-demo-alb/0a1b2c3d4e5f6001")}),
        res("aws_kms_key", "data", {"id": "0a1b2c3d-0000-4000-8000-000000000001",
            "arn": arn("kms", "key/0a1b2c3d-0000-4000-8000-000000000001")}),
        res("aws_iam_role", "app", {"id": "cms-demo-app", "name": "cms-demo-app",
            "arn": f"arn:aws:iam::{ACCOUNT}:role/cms-demo-app"}),
    ]  # fmt: skip
    return {"version": 4, "terraform_version": "1.9.8", "serial": 7, "lineage": uid("lineage"), "outputs": {},
            "resources": resources}  # fmt: skip


def render(doc) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def build_inputs() -> dict[Path, str]:
    return {
        SAMPLES / "boundary.yaml": boundary_yaml(),
        SAMPLES / "ssp.json": render(ssp()),
        SAMPLES / "aws-config-export.json": render(config_export()),
        SAMPLES / "terraform.tfstate": render(terraform_state()),
    }


RUNS = {
    "ssp-vs-aws-config": [
        "--declared",
        "samples/ssp.json",
        "--actual",
        "samples/aws-config-export.json",
    ],
    "yaml-vs-aws-config": [
        "--declared",
        "samples/boundary.yaml",
        "--actual",
        "samples/aws-config-export.json",
    ],
    "yaml-vs-terraform": [
        "--declared",
        "samples/boundary.yaml",
        "--actual",
        "samples/terraform.tfstate",
    ],
}


def build_outputs() -> dict[Path, str]:
    import contextlib
    import io
    import os

    sys.path.insert(0, str(ROOT / "src"))
    from boundary_drift_detector.cli import main

    files = {}
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        for name, args in RUNS.items():
            with (
                tempfile.TemporaryDirectory() as tmp,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                main(["check", *args, "-o", tmp, "--timestamp", TIMESTAMP])
                for p in sorted(Path(tmp).iterdir()):
                    files[SAMPLES / "outputs" / name / p.name] = p.read_text(encoding="utf-8")
    finally:
        os.chdir(cwd)
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    inputs = build_inputs()
    if args.check:
        files = {**inputs, **build_outputs()}
        stale = [p for p, t in files.items() if not p.is_file() or p.read_text(encoding="utf-8") != t]
        for p in stale:
            print(f"out of date: {p.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    for path, text in inputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for path, text in build_outputs().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print("samples written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
