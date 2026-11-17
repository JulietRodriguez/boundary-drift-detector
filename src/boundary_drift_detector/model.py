"""Shared types: a resource (declared or actual) and a drift finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["critical", "high", "medium", "low", "info"].index(self.value)

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            raise ValueError(f"unknown severity {value!r} (choose from {', '.join(s.value for s in cls)})") from exc


@dataclass
class Resource:
    """One cloud resource, normalized from whatever format it came in.

    ``encrypted`` and ``public`` are True / False when the source says so, and
    None when it doesn't (unknown is reported as unknown, never guessed).
    """

    type: str  # AWS CloudFormation-style type, e.g. AWS::S3::Bucket
    id: str  # resource ID (bucket name, instance ID, ...)
    arn: str | None = None
    name: str | None = None
    region: str | None = None
    account: str | None = None
    encrypted: bool | None = None
    public: bool | None = None
    source: str = ""  # where it came from: file name, "aws-config", "terraform", "ssp", "yaml"
    ref: str | None = None  # OSCAL inventory-item UUID when declared in an SSP
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Drift:
    kind: str  # undeclared, missing, region, encryption, public, unverified
    severity: Severity
    message: str
    declared: Resource | None
    actual: Resource | None
    control: str  # the NIST SP 800-53 control the drift bears on

    @property
    def resource(self) -> Resource:
        return self.actual or self.declared  # type: ignore[return-value]

    def to_dict(self) -> dict:
        r = self.resource
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "control": self.control,
            "resource_type": r.type,
            "resource_id": r.id,
            "arn": r.arn,
            "region": r.region,
            "message": self.message,
        }
