"""What actually exists: AWS Config inventory exports and Terraform state.

AWS Config formats accepted (all as the CLI writes them):

* ``aws configservice select-resource-config`` / ``select-aggregate-resource-config``
  -> ``{"Results": ["<json string>", ...]}``
* ``aws configservice batch-get-resource-config`` -> ``{"baseConfigurationItems": [...]}``
* A Config snapshot file -> ``{"configurationItems": [...]}``
* A plain JSON list of configuration items.

Terraform: a state file (``terraform show -json`` state or the raw
``terraform.tfstate``, version 4). Helper resources such as
``aws_s3_bucket_public_access_block`` are folded into the bucket they configure.

Encryption and public exposure are read only where the source states them; when
it doesn't, the value stays None (unknown) and the report says "unverified".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from boundary_drift_detector.awstypes import (
    TERRAFORM_TO_AWS,
    arn_account,
    arn_region,
    normalize_type,
)
from boundary_drift_detector.declared import InputError
from boundary_drift_detector.model import Resource

OPEN_CIDRS = ("0.0.0.0/0", "::/0")


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


# --- AWS Config ------------------------------------------------------------------------------


def _s3_public(supp: dict) -> bool | None:
    pab = _maybe_json(supp.get("PublicAccessBlockConfiguration")) or {}
    keys = (
        "blockPublicAcls",
        "ignorePublicAcls",
        "blockPublicPolicy",
        "restrictPublicBuckets",
    )
    if pab and all(pab.get(k) is True for k in keys):
        return False
    acl = _maybe_json(supp.get("AccessControlList")) or {}
    grants = acl.get("grantList", []) if isinstance(acl, dict) else []
    public_grantee = any("AllUsers" in json.dumps(g) or "AuthenticatedUsers" in json.dumps(g) for g in grants)
    policy = _maybe_json(supp.get("BucketPolicy")) or {}
    text = policy.get("policyText") if isinstance(policy, dict) else None
    statements = (_maybe_json(text) or {}).get("Statement", []) if text else []
    if isinstance(statements, dict):
        statements = [statements]
    public_policy = any(
        s.get("Effect") == "Allow" and s.get("Principal") in ("*", {"AWS": "*"}) and not s.get("Condition")
        for s in statements
        if isinstance(s, dict)
    )
    if public_grantee or public_policy:
        return True
    if pab or acl or policy:
        return False  # we looked at the access settings and found nothing public
    return None


def _sg_public(cfg: dict) -> bool | None:
    perms = cfg.get("ipPermissions")
    if perms is None:
        return None
    for perm in perms:
        cidrs = list(perm.get("ipRanges", []))
        cidrs += [r.get("cidrIp") for r in perm.get("ipv4Ranges", [])]
        cidrs += [r.get("cidrIpv6") for r in perm.get("ipv6Ranges", [])]
        if any(c in OPEN_CIDRS for c in cidrs):
            return True
    return False


def _config_attributes(rtype: str, cfg: dict, supp: dict) -> tuple[bool | None, bool | None]:
    """(encrypted, public) for the resource types where Config records them."""
    if rtype == "AWS::S3::Bucket":
        sse = _maybe_json(supp.get("ServerSideEncryptionConfiguration"))
        encrypted = True if sse else None  # absent: Config doesn't say, so unknown
        return encrypted, _s3_public(supp)
    if rtype == "AWS::EC2::Volume":
        return cfg.get("encrypted"), None
    if rtype == "AWS::EC2::Instance":
        if "publicIpAddress" in cfg or "networkInterfaces" in cfg:
            return None, bool(cfg.get("publicIpAddress"))
        return None, None
    if rtype in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
        return cfg.get("storageEncrypted"), cfg.get("publiclyAccessible")
    if rtype == "AWS::ElasticLoadBalancingV2::LoadBalancer":
        scheme = cfg.get("scheme")
        return None, (scheme == "internet-facing") if scheme else None
    if rtype == "AWS::EC2::SecurityGroup":
        return None, _sg_public(cfg)
    if rtype == "AWS::DynamoDB::Table":
        return (
            True,
            False,
        )  # DynamoDB always encrypts at rest and has no public endpoint setting
    if rtype == "AWS::EFS::FileSystem":
        return cfg.get("Encrypted", cfg.get("encrypted")), None
    return None, None


def config_item_to_resource(item: dict, source: str = "aws-config") -> Resource:
    rtype = normalize_type(item.get("resourceType"))
    cfg = _maybe_json(item.get("configuration")) or {}
    supp = _maybe_json(item.get("supplementaryConfiguration")) or {}
    if not isinstance(cfg, dict):
        cfg = {}
    if not isinstance(supp, dict):
        supp = {}
    arn = item.get("arn") or item.get("ARN")
    encrypted, public = _config_attributes(rtype, cfg, supp)
    return Resource(
        type=rtype,
        id=str(item.get("resourceId") or ""),
        arn=arn,
        name=item.get("resourceName"),
        region=item.get("awsRegion") or arn_region(arn),
        account=item.get("accountId") or arn_account(arn),
        encrypted=encrypted,
        public=public,
        source=source,
    )


def _config_items(data: Any) -> list[dict] | None:
    if isinstance(data, dict):
        if "Results" in data:
            return [_maybe_json(r) for r in data["Results"]]
        for key in (
            "baseConfigurationItems",
            "configurationItems",
            "ConfigurationItems",
        ):
            if key in data:
                return list(data[key])
        return None
    if isinstance(data, list) and all(isinstance(x, dict) and "resourceType" in x for x in data):
        return data
    return None


# --- Terraform -----------------------------------------------------------------------------------


def _tf_instances(state: dict) -> list[tuple[str, dict]]:
    out = []
    if "values" in state:  # `terraform show -json`

        def walk(module: dict) -> None:
            for r in module.get("resources", []):
                if r.get("mode", "managed") == "managed":
                    out.append((r["type"], r.get("values", {})))
            for child in module.get("child_modules", []):
                walk(child)

        walk(state["values"].get("root_module", {}))
        return out
    for r in state.get("resources", []):
        if r.get("mode", "managed") != "managed":
            continue
        for inst in r.get("instances", []):
            out.append((r["type"], inst.get("attributes", {})))
    return out


def terraform_to_resources(state: dict, source: str = "terraform") -> tuple[list[Resource], int]:
    """Resources in the state, and the number of helper resources folded into others or skipped."""
    instances = _tf_instances(state)
    pab = {a.get("bucket"): a for t, a in instances if t == "aws_s3_bucket_public_access_block"}
    sse = {a.get("bucket") for t, a in instances if t == "aws_s3_bucket_server_side_encryption_configuration"}
    resources, skipped = [], 0
    for tf_type, a in instances:
        if tf_type not in TERRAFORM_TO_AWS:
            skipped += 1
            continue
        rtype = TERRAFORM_TO_AWS[tf_type]
        tags = a.get("tags") if isinstance(a.get("tags"), dict) else {}
        rid = str(a.get("id") or a.get("bucket") or a.get("name") or "")
        arn = a.get("arn")
        encrypted: bool | None = None
        public: bool | None = None
        if tf_type == "aws_s3_bucket":
            block = pab.get(rid)
            keys = (
                "block_public_acls",
                "ignore_public_acls",
                "block_public_policy",
                "restrict_public_buckets",
            )
            if block is not None:
                public = not all(block.get(k) is True for k in keys)
            if a.get("acl") in ("public-read", "public-read-write"):
                public = True
            if rid in sse or a.get("server_side_encryption_configuration"):
                encrypted = True
        elif tf_type == "aws_ebs_volume":
            encrypted = a.get("encrypted")
        elif tf_type == "aws_instance":
            if "public_ip" in a or "associate_public_ip_address" in a:
                public = bool(a.get("public_ip")) or bool(a.get("associate_public_ip_address"))
        elif tf_type in ("aws_db_instance", "aws_rds_cluster"):
            encrypted, public = a.get("storage_encrypted"), a.get("publicly_accessible")
        elif tf_type in ("aws_lb", "aws_alb"):
            if "internal" in a:
                public = not a["internal"]
        elif tf_type == "aws_security_group":
            if "ingress" in a:
                public = any(
                    c in OPEN_CIDRS
                    for rule in a.get("ingress") or []
                    for c in (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or [])
                )
        elif tf_type == "aws_dynamodb_table":
            encrypted, public = True, False
        elif tf_type == "aws_efs_file_system":
            encrypted = a.get("encrypted")
        resources.append(
            Resource(
                type=rtype,
                id=rid,
                arn=arn,
                name=a.get("name") or a.get("bucket") or tags.get("Name"),
                region=a.get("region") or arn_region(arn),
                account=arn_account(arn),
                encrypted=encrypted,
                public=public,
                source=source,
            )
        )
    return resources, skipped


# --- loading -----------------------------------------------------------------------------------


def load_actual(path: str | Path) -> tuple[list[Resource], str, int]:
    """(resources, format name, helper resources skipped) for an inventory file."""
    p = Path(path)
    if not p.is_file():
        raise InputError(f"{p}: file not found")
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{p}: not valid JSON ({exc.msg})") from exc
    if isinstance(data, dict) and (("resources" in data and "version" in data) or "values" in data):
        resources, skipped = terraform_to_resources(data, source=p.name)
        return resources, "terraform", skipped
    items = _config_items(data)
    if items is None:
        raise InputError(
            f"{p}: not an AWS Config export (select-resource-config, batch-get-resource-config, snapshot) "
            "or a Terraform state file"
        )
    bad = [i for i, x in enumerate(items) if not isinstance(x, dict) or not x.get("resourceType")]
    if bad:
        raise InputError(f"{p}: configuration item {bad[0]} has no resourceType")
    return [config_item_to_resource(x, source=p.name) for x in items], "aws-config", 0
