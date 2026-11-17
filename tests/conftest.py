from __future__ import annotations

import json
from pathlib import Path

import pytest

from boundary_drift_detector.declared import Boundary
from boundary_drift_detector.model import Resource

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
SCHEMAS = ROOT / "schemas"
COMPAT = Path(__file__).parent / "fixtures" / "compat"


def res(rtype="AWS::S3::Bucket", rid="b1", **kw) -> Resource:
    return Resource(type=rtype, id=rid, **kw)


def boundary(*resources, **kw) -> Boundary:
    return Boundary(name="Test", resources=list(resources), **kw)


@pytest.fixture
def write(tmp_path):
    def _write(name, content):
        p = tmp_path / name
        p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return p

    return _write


class FakeConfigClient:
    """Stands in for boto3's AWS Config client; returns canned pages."""

    def __init__(self, items, page_size=2):
        self.rows = [json.dumps(i) for i in items]
        self.page_size = page_size
        self.calls = []

    def _page(self, kwargs):
        self.calls.append(kwargs)
        start = int(kwargs.get("NextToken", 0))
        end = start + self.page_size
        page = {"Results": self.rows[start:end]}
        if end < len(self.rows):
            page["NextToken"] = str(end)
        return page

    def select_resource_config(self, **kwargs):
        return self._page(kwargs)

    def select_aggregate_resource_config(self, **kwargs):
        return self._page(kwargs)
