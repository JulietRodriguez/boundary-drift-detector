"""Optional live mode: read the inventory straight from AWS Config with boto3.

Uses AWS Config's advanced query (``select_resource_config``), or
``select_aggregate_resource_config`` when an aggregator name is given, so one
call covers every resource type Config records. Read-only: the IAM permissions
needed are ``config:SelectResourceConfig`` (or
``config:SelectAggregateResourceConfig``).

The client is passed in, so tests use a fake one and need no AWS account.
"""

from __future__ import annotations

import json
from typing import Any

from boundary_drift_detector.actual import config_item_to_resource
from boundary_drift_detector.model import Resource

QUERY = (
    "SELECT arn, resourceType, resourceId, resourceName, awsRegion, accountId, "
    "configuration, supplementaryConfiguration"
)


def make_client(region: str | None = None, profile: str | None = None):  # pragma: no cover - needs boto3
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("live mode needs boto3: pip install 'boundary-drift-detector[aws]'") from exc
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("config")


def collect(client: Any, aggregator: str | None = None, page_size: int = 100) -> list[Resource]:
    items: list[Resource] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"Expression": QUERY, "Limit": page_size}
        if token:
            kwargs["NextToken"] = token
        if aggregator:
            kwargs["ConfigurationAggregatorName"] = aggregator
            page = client.select_aggregate_resource_config(**kwargs)
        else:
            page = client.select_resource_config(**kwargs)
        for row in page.get("Results", []):
            items.append(config_item_to_resource(json.loads(row), source="aws-config (live)"))
        token = page.get("NextToken")
        if not token:
            return items
