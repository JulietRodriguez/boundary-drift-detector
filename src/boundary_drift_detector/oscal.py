"""Write the drift check as OSCAL 1.1.2 Assessment Results.

* Each drift is an **observation** (method TEST). Its subject is the resource:
  the SSP's own inventory-item when the boundary came from an SSP, otherwise an
  inventory-item defined in the result's ``local-definitions`` (that's where
  undeclared resources go, since by definition the SSP doesn't list them).
* Drifts are grouped into one not-satisfied **finding** per control (CM-8
  inventory, SC-28 encryption at rest, SC-7 boundary protection), with the
  worst severity as a ``severity`` prop. ato-readiness-checker reads these
  findings directly. "Unverified" items (an expectation the inventory can't
  confirm either way) stay observations only: not knowing isn't a failure.
* No "satisfied" findings are written: a clean drift check shows the
  inventory matches the boundary, not that CM-8 or SC-7 is fully implemented.

UUIDs are UUIDv5 values derived from the boundary name and the resource, so the
same inputs give the same file.
"""

from __future__ import annotations

import uuid
from collections import defaultdict

from boundary_drift_detector import OSCAL_VERSION, __version__
from boundary_drift_detector.compare import DriftReport
from boundary_drift_detector.model import Drift, Resource

NS = "https://github.com/JulietRodriguez/boundary-drift-detector/ns/oscal"
_ROOT = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/JulietRodriguez/boundary-drift-detector")
CONTROL_TITLES = {
    "cm-8": "System Component Inventory",
    "sc-28": "Protection of Information at Rest",
    "sc-7": "Boundary Protection",
}
METHOD_DOC = "https://github.com/JulietRodriguez/boundary-drift-detector/blob/main/docs/design-notes.md"


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_ROOT, "|".join(parts)))


def _prop(name: str, value: str) -> dict:
    return {"name": name, "ns": NS, "value": value}


def _resource_key(r: Resource) -> str:
    return r.arn or f"{r.type}|{r.id}|{r.region}"


def _inventory_item(r: Resource, seed: str) -> dict:
    props = [_prop("asset-id", r.arn or r.id), _prop("resource-type", r.type)]
    if r.region:
        props.append(_prop("region", r.region))
    return {
        "uuid": _uuid(seed, "inv", _resource_key(r)),
        "description": f"{r.type} {r.name or r.id} (from {r.source or 'inventory'})",
        "props": props,
    }


def to_oscal(report: DriftReport, *, timestamp: str) -> dict:
    seed = report.boundary.name
    local_items: dict[str, dict] = {}

    def subject_for(d: Drift) -> dict:
        declared = d.declared
        if declared is not None and declared.ref:
            return {"subject-uuid": declared.ref, "type": "inventory-item"}
        r = d.resource
        item = local_items.setdefault(_resource_key(r), _inventory_item(r, seed))
        return {"subject-uuid": item["uuid"], "type": "inventory-item"}

    observations = []
    by_control: dict[str, list[tuple[Drift, str]]] = defaultdict(list)
    for d in report.drifts:
        r = d.resource
        obs_uuid = _uuid(seed, "obs", d.kind, _resource_key(r))
        observations.append(
            {
                "uuid": obs_uuid,
                "title": f"{d.kind}: {r.type} {r.name or r.id}",
                "description": d.message,
                "props": [
                    _prop("drift-kind", d.kind),
                    _prop("severity", d.severity.value),
                ],
                "methods": ["TEST"],
                "types": ["finding"],
                "subjects": [subject_for(d)],
                "collected": timestamp,
            }
        )
        if d.kind != "unverified":
            by_control[d.control].append((d, obs_uuid))

    findings = []
    for control in sorted(by_control):
        items = by_control[control]
        worst = min((d.severity for d, _ in items), key=lambda s: s.rank)
        kinds = sorted({d.kind for d, _ in items})
        findings.append(
            {
                "uuid": _uuid(seed, "finding", control),
                "title": f"{control.upper()} {CONTROL_TITLES[control]}: boundary drift",
                "description": f"{len(items)} boundary drift observation(s) ({', '.join(kinds)}) bear on "
                f"{control.upper()}. See the related observations.",
                "props": [_prop("severity", worst.value)],
                "target": {
                    "type": "objective-id",
                    "target-id": f"{control}_obj",
                    "status": {"state": "not-satisfied"},
                },
                "related-observations": [{"observation-uuid": u} for _, u in items],
            }
        )

    method_uuid = _uuid(seed, "method")
    result: dict = {
        "uuid": _uuid(seed, "result", timestamp),
        "title": f"Authorization boundary drift check: {report.boundary.name}",
        "description": (
            f"Compared {report.declared_count} declared resources with {report.actual_count} resources in the "
            f"inventory ({', '.join(report.actual_sources) or 'live AWS Config'}). {len(report.matches)} matched."
        ),
        "start": timestamp,
        "end": timestamp,
        "props": [
            _prop("declared-resources", str(report.declared_count)),
            _prop("inventory-resources", str(report.actual_count)),
            _prop("matched-resources", str(len(report.matches))),
        ],
        "reviewed-controls": {
            "control-selections": [
                {
                    "description": "Controls a boundary drift check bears on.",
                    "include-controls": [{"control-id": c} for c in CONTROL_TITLES],
                }
            ]
        },
    }
    if local_items:
        result["local-definitions"] = {"inventory-items": list(local_items.values())}
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings

    return {
        "assessment-results": {
            "uuid": _uuid(seed, "ar", timestamp),
            "metadata": {
                "title": f"Boundary drift check: {report.boundary.name}",
                "last-modified": timestamp,
                "version": __version__,
                "oscal-version": OSCAL_VERSION,
                "props": [_prop("generator", f"boundary-drift-detector {__version__}")],
            },
            "import-ap": {
                "href": f"#{method_uuid}",
                "remarks": "No assessment plan applies; this points at the drift check method.",
            },
            "results": [result],
            "back-matter": {
                "resources": [
                    {
                        "uuid": method_uuid,
                        "title": f"boundary-drift-detector {__version__} method",
                        "rlinks": [{"href": METHOD_DOC}],
                    }
                ]
            },
        }
    }
