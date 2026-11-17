"""Match declared resources to actual ones and report the differences.

Matching, strongest first: ARN, then (type, resource ID), then (type, name).
Most AWS resources have an ARN in both the SSP and AWS Config, so nearly all
matches are exact; the fallbacks cover hand-written boundaries that list a
bucket by name or an instance by ID.

Drift kinds and default severities:

=============  ========  ==========================================================  =======
kind           severity  meaning                                                     control
=============  ========  ==========================================================  =======
undeclared     high      exists but isn't in the boundary (critical if public)       CM-8
missing        medium    in the boundary but not found                               CM-8
region         high      in a different region than declared, or outside the         CM-8
                         boundary's regions
encryption     high      expected encrypted, found unencrypted                       SC-28
public         critical  expected private, found publicly exposed                    SC-7
unverified     info      an expectation couldn't be checked (the source doesn't      (none)
                         record encryption or exposure for this resource)
=============  ========  ==========================================================  =======
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from boundary_drift_detector.awstypes import DEFAULT_IGNORED_TYPES
from boundary_drift_detector.declared import Boundary
from boundary_drift_detector.model import Drift, Resource, Severity

# Boundary-wide expectations (expect: {encrypted, public}) apply only to the types
# where encryption at rest / public exposure is a property this tool can read.
# A rule written on an individual resource always applies.
ENCRYPTION_TYPES = frozenset(
    {"AWS::S3::Bucket", "AWS::EC2::Volume", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DynamoDB::Table",
     "AWS::EFS::FileSystem"}
)  # fmt: skip
EXPOSURE_TYPES = frozenset(
    {"AWS::S3::Bucket", "AWS::EC2::Instance", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster",
     "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::EC2::SecurityGroup", "AWS::DynamoDB::Table"}
)  # fmt: skip

# AWS Config reports IAM and other global resources with region "global".
GLOBAL_REGIONS = frozenset({"global", "aws-global"})

KINDS = ("undeclared", "missing", "region", "encryption", "public", "unverified")


@dataclass
class DriftReport:
    boundary: Boundary
    actual_sources: list[str]
    declared_count: int
    actual_count: int  # in scope, after ignored types
    ignored: Counter
    matches: list[tuple[Resource, Resource, str]]  # (declared, actual, how matched)
    drifts: list[Drift]
    allowed_regions: set[str]
    allowed_accounts: set[str]
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = Counter(d.kind for d in self.drifts)
        return {k: c.get(k, 0) for k in KINDS}

    def severity_counts(self) -> dict[str, int]:
        c = Counter(d.severity.value for d in self.drifts)
        return {s.value: c.get(s.value, 0) for s in Severity}

    def failed(self, fail_on: Severity | None) -> bool:
        return fail_on is not None and any(d.severity.rank <= fail_on.rank for d in self.drifts)


def _index(actual: list[Resource]) -> dict[str, list[Resource]]:
    idx: dict[str, list[Resource]] = defaultdict(list)
    for r in actual:
        if r.arn:
            idx[f"arn|{r.arn}"].append(r)
        for value in {r.id, r.name} - {None, ""}:
            idx[f"tn|{r.type}|{value}"].append(r)
    return idx


def _candidates(d: Resource, idx: dict[str, list[Resource]]) -> tuple[list[Resource], str]:
    if d.arn and idx.get(f"arn|{d.arn}"):
        return idx[f"arn|{d.arn}"], "arn"
    for value in (d.id, d.name):
        found = idx.get(f"tn|{d.type}|{value}") if value else None
        if found:
            # report which actual field matched: its resource ID, or only its name
            return found, "id" if any(c.id == value for c in found) else "name"
    return [], ""


def compare(
    boundary: Boundary,
    actual: list[Resource],
    *,
    actual_sources: list[str] | None = None,
    regions: set[str] | None = None,
    accounts: set[str] | None = None,
    expect_encrypted: bool | None = None,
    expect_public: bool | None = None,
) -> DriftReport:
    notes: list[str] = []
    ignored_types = DEFAULT_IGNORED_TYPES | boundary.ignore_types
    declared_types = {d.type for d in boundary.resources}
    ignored: Counter = Counter()
    in_scope = []
    for r in actual:
        if r.type in ignored_types and r.type not in declared_types:
            ignored[r.type] += 1
        else:
            in_scope.append(r)

    allowed_regions = (
        regions
        or boundary.regions
        or {d.region for d in boundary.resources if d.region and d.region not in GLOBAL_REGIONS}
    )
    if not (regions or boundary.regions) and allowed_regions:
        notes.append(f"Allowed regions taken from the declared resources: {', '.join(sorted(allowed_regions))}.")
    allowed_accounts = accounts or boundary.accounts or {d.account for d in boundary.resources if d.account}
    want_encrypted = expect_encrypted if expect_encrypted is not None else boundary.expect_encrypted
    want_public = expect_public if expect_public is not None else boundary.expect_public

    idx = _index(in_scope)
    used: set[int] = set()
    matches: list[tuple[Resource, Resource, str]] = []
    drifts: list[Drift] = []

    for d in boundary.resources:
        cands, how = _candidates(d, idx)
        cands = [c for c in cands if id(c) not in used]
        if d.region:
            cands.sort(key=lambda c: c.region != d.region)
        if not cands:
            drifts.append(
                Drift(
                    "missing",
                    Severity.MEDIUM,
                    "Declared in the boundary but not found in the inventory.",
                    d,
                    None,
                    "cm-8",
                )
            )
            continue
        a = cands[0]
        used.add(id(a))
        matches.append((d, a, how))
        drifts.extend(_check_match(d, a, allowed_regions, want_encrypted, want_public))

    for a in in_scope:
        if id(a) in used:
            continue
        where = []
        if allowed_regions and a.region and a.region not in allowed_regions | GLOBAL_REGIONS:
            where.append(f"in region {a.region}, outside the boundary's regions")
        if allowed_accounts and a.account and a.account not in allowed_accounts:
            where.append(f"in account {a.account}, outside the boundary's accounts")
        exposed = a.public is True
        msg = "Exists in the inventory but is not declared in the boundary"
        msg += (" (" + "; ".join(where) + ")") if where else ""
        msg += ", and it is publicly exposed." if exposed else "."
        drifts.append(
            Drift(
                "undeclared",
                Severity.CRITICAL if exposed else Severity.HIGH,
                msg,
                None,
                a,
                "cm-8",
            )
        )

    drifts.sort(
        key=lambda x: (
            x.severity.rank,
            KINDS.index(x.kind),
            x.resource.type,
            x.resource.id,
        )
    )
    return DriftReport(
        boundary=boundary,
        actual_sources=actual_sources or [],
        declared_count=len(boundary.resources),
        actual_count=len(in_scope),
        ignored=ignored,
        matches=matches,
        drifts=drifts,
        allowed_regions=allowed_regions,
        allowed_accounts=allowed_accounts,
        notes=notes,
    )


def _check_match(
    d: Resource,
    a: Resource,
    allowed_regions: set[str],
    want_encrypted: bool | None,
    want_public: bool | None,
) -> list[Drift]:
    out = []
    if a.region in GLOBAL_REGIONS or d.region in GLOBAL_REGIONS:
        pass  # global resources have no region to drift
    elif d.region and a.region and d.region != a.region:
        out.append(
            Drift(
                "region",
                Severity.HIGH,
                f"Declared in {d.region}, found in {a.region}.",
                d,
                a,
                "cm-8",
            )
        )
    elif allowed_regions and a.region and a.region not in allowed_regions:
        out.append(
            Drift(
                "region",
                Severity.HIGH,
                f"Found in {a.region}, outside the boundary's regions.",
                d,
                a,
                "cm-8",
            )
        )

    expected = d.encrypted if d.encrypted is not None else (want_encrypted if a.type in ENCRYPTION_TYPES else None)
    if expected is True:
        if a.encrypted is False:
            out.append(
                Drift(
                    "encryption",
                    Severity.HIGH,
                    "Expected encrypted at rest; found unencrypted.",
                    d,
                    a,
                    "sc-28",
                )
            )
        elif a.encrypted is None:
            out.append(
                Drift(
                    "unverified",
                    Severity.INFO,
                    "Expected encrypted, but the inventory doesn't record encryption for this resource.",
                    d,
                    a,
                    "",
                )
            )
    expected = d.public if d.public is not None else (want_public if a.type in EXPOSURE_TYPES else None)
    if expected is False:
        if a.public is True:
            out.append(
                Drift(
                    "public",
                    Severity.CRITICAL,
                    "Expected private; found publicly exposed.",
                    d,
                    a,
                    "sc-7",
                )
            )
        elif a.public is None:
            out.append(
                Drift(
                    "unverified",
                    Severity.INFO,
                    "Expected private, but the inventory doesn't record public exposure for this resource.",
                    d,
                    a,
                    "",
                )
            )
    return out
