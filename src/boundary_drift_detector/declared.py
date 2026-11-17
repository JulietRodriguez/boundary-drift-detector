"""The declared authorization boundary: what the SSP says is in the system.

Two formats:

* An OSCAL SSP (JSON). Each ``system-implementation/inventory-items`` entry is a
  declared resource. Props read (any namespace): ``asset-id`` (ARN or resource
  ID), ``resource-type`` (AWS::S3::Bucket or aws_s3_bucket), ``region``,
  ``public`` / ``is-public`` (yes/no), ``encrypted`` (yes/no), ``asset-name``.
  This is what oscal-ssp-generator writes.
* A simple YAML file, for teams that don't have an OSCAL SSP yet::

      boundary:
        name: CMS-DEMO production
        accounts: ["111122223333"]
        regions: [us-east-1]
        expect: {encrypted: true, public: false}   # rules for every resource
        ignore_types: [AWS::EC2::NetworkInterface]
      resources:
        - id: arn:aws:s3:::cms-demo-case-files
          type: AWS::S3::Bucket
          public: false

Boundary-wide rules (``regions``, ``accounts``, ``expect``) can also be given on
the command line, which is how they are applied to an SSP.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from boundary_drift_detector.awstypes import (
    TERRAFORM_SETTINGS_TYPES,
    arn_account,
    arn_region,
    arn_resource_id,
    normalize_type,
)
from boundary_drift_detector.model import Resource


class InputError(ValueError):
    """An input file can't be read as a boundary or an inventory."""


@dataclass
class Boundary:
    name: str
    resources: list[Resource]
    regions: set[str] = field(default_factory=set)  # empty = derive from declared resources
    accounts: set[str] = field(default_factory=set)
    expect_encrypted: bool | None = None
    expect_public: bool | None = None
    ignore_types: set[str] = field(default_factory=set)
    source: str = ""
    ssp_uuid: str | None = None
    settings_skipped: int = 0  # declared Terraform settings resources (not assets) that aren't compared


def _yes_no(value: Any, where: str) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("yes", "true", "y", "1"):
        return True
    if text in ("no", "false", "n", "0"):
        return False
    raise InputError(f"{where}: expected yes/no, got {value!r}")


def _props(item: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in item.get("props", []) or []:
        name = str(p.get("name", "")).lower()
        if name and name not in out:
            out[name] = str(p.get("value", ""))
    return out


def _resource(rid: str, rtype: str, *, where: str, **attrs: Any) -> Resource:
    arn = rid if rid.startswith("arn:") else attrs.pop("arn", None)
    if arn and rid == arn:
        rid = arn_resource_id(arn)
        if not attrs.get("name"):
            attrs["name"] = rid  # lets "name" matching work when AWS uses an opaque resource ID
    region = attrs.pop("region", None) or arn_region(arn)
    account = attrs.pop("account", None) or arn_account(arn)
    if not rtype:
        raise InputError(f"{where}: resource type is required (e.g. AWS::S3::Bucket)")
    return Resource(
        type=normalize_type(rtype),
        id=rid,
        arn=arn,
        region=region,
        account=account,
        **attrs,
    )


def _from_ssp(root: dict, source: str) -> Boundary:
    items = root.get("system-implementation", {}).get("inventory-items", []) or []
    if not items:
        raise InputError(f"{source}: the SSP has no system-implementation/inventory-items to compare")
    resources = []
    skipped = 0
    for i, item in enumerate(items):
        props = _props(item)
        where = f"{source}: inventory-items[{i}]"
        if (props.get("resource-type") or props.get("asset-type") or "") in TERRAFORM_SETTINGS_TYPES:
            skipped += 1
            continue
        rid = props.get("asset-id") or props.get("resource-id") or ""
        if not rid:
            raise InputError(f"{where}: needs an asset-id prop (ARN or resource ID)")
        resources.append(
            _resource(
                rid,
                props.get("resource-type") or props.get("asset-type") or "",
                where=where,
                name=props.get("asset-name") or None,
                region=props.get("region") or None,
                public=_yes_no(props.get("public", props.get("is-public")), where),
                encrypted=_yes_no(props.get("encrypted"), where),
                source="ssp",
                ref=item.get("uuid"),
            )
        )
    name = root.get("system-characteristics", {}).get("system-name") or root.get("metadata", {}).get("title", source)
    return Boundary(
        name=str(name), resources=resources, source=source, ssp_uuid=root.get("uuid"), settings_skipped=skipped
    )


def _from_yaml(data: dict, source: str) -> Boundary:
    b = data.get("boundary") or {}
    if not isinstance(b, dict) or not b.get("name"):
        raise InputError(f"{source}: boundary.name is required")
    expect = b.get("expect") or {}
    raw = data.get("resources") or []
    if not isinstance(raw, list):
        raise InputError(f"{source}: resources must be a list")
    resources = []
    for i, r in enumerate(raw):
        where = f"{source}: resources[{i}]"
        if not isinstance(r, dict) or not r.get("id"):
            raise InputError(f"{where}: needs an id (ARN or resource ID)")
        resources.append(
            _resource(
                str(r["id"]),
                str(r.get("type", "")),
                where=where,
                name=r.get("name"),
                region=r.get("region"),
                public=_yes_no(r.get("public"), where),
                encrypted=_yes_no(r.get("encrypted"), where),
                source="yaml",
            )
        )
    return Boundary(
        name=str(b["name"]),
        resources=resources,
        regions={str(x) for x in b.get("regions") or []},
        accounts={str(x) for x in b.get("accounts") or []},
        expect_encrypted=_yes_no(expect.get("encrypted"), f"{source}: boundary.expect"),
        expect_public=_yes_no(expect.get("public"), f"{source}: boundary.expect"),
        ignore_types={normalize_type(t) for t in b.get("ignore_types") or []},
        source=source,
    )


def load_boundary(path: str | Path) -> Boundary:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"{p}: file not found")
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(f"{p}: not valid JSON ({exc.msg})") from exc
    else:
        import yaml

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise InputError(f"{p}: not valid YAML ({exc})") from exc
    if not isinstance(data, dict):
        raise InputError(f"{p}: expected a mapping at the top level")
    if "system-security-plan" in data:
        return _from_ssp(data["system-security-plan"], p.name)
    if "boundary" in data:
        return _from_yaml(data, p.name)
    raise InputError(f"{p}: not an OSCAL SSP or a boundary YAML file (no 'system-security-plan' or 'boundary' key)")
