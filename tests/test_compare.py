"""Matching and drift rules."""

import pytest

from boundary_drift_detector.actual import load_actual
from boundary_drift_detector.compare import compare
from boundary_drift_detector.declared import load_boundary
from boundary_drift_detector.model import Severity
from tests.conftest import COMPAT, SAMPLES, boundary, res


def kinds(report):
    return [(d.kind, d.severity.value, d.resource.id) for d in report.drifts]


def test_sample_config_drift():
    b = load_boundary(SAMPLES / "ssp.json")
    actual, _, _ = load_actual(SAMPLES / "aws-config-export.json")
    r = compare(b, actual)
    assert r.counts() == {"undeclared": 2, "missing": 1, "region": 0, "encryption": 1, "public": 1, "unverified": 1}
    assert r.severity_counts() == {"critical": 2, "high": 2, "medium": 1, "low": 0, "info": 1}
    assert r.ignored == {"AWS::Config::ResourceCompliance": 1}
    assert r.declared_count == 9 and r.actual_count == 10 and len(r.matches) == 8
    top = r.drifts[0]
    assert (top.kind, top.resource.id) == ("undeclared", "cms-demo-export-tmp")
    assert "us-west-2, outside the boundary's regions" in top.message and "publicly exposed" in top.message


def test_sample_terraform_is_clean():
    r = compare(load_boundary(SAMPLES / "boundary.yaml"), load_actual(SAMPLES / "terraform.tfstate")[0])
    assert r.drifts == [] and len(r.matches) == 9
    assert {how for *_, how in r.matches} == {"arn"}


def test_oscal_ssp_generator_round_trip():
    b = load_boundary(COMPAT / "oscal-ssp-generator_ssp.json")
    r = compare(b, load_actual(COMPAT / "oscal-ssp-generator_terraform.tfstate")[0])
    assert r.drifts == [] and len(r.matches) == 10


def test_match_by_id_and_name():
    b = boundary(res(rid="bucket-a"), res("AWS::IAM::Role", "cms-role", name="cms-role"))
    actual = [res(rid="bucket-a", arn="arn:aws:s3:::bucket-a"), res("AWS::IAM::Role", "AROA123", name="cms-role")]
    r = compare(b, actual)
    assert [how for *_, how in r.matches] == ["id", "name"] and r.drifts == []


def test_same_name_prefers_declared_region():
    b = boundary(res(rid="q", region="us-west-2"))
    r = compare(b, [res(rid="q", region="us-east-1"), res(rid="q", region="us-west-2")])
    assert r.matches[0][1].region == "us-west-2"
    assert [d.kind for d in r.drifts] == ["undeclared"]


def test_region_drift_and_allowed_regions():
    r = compare(boundary(res(rid="a", region="us-east-1")), [res(rid="a", region="us-west-2")])
    assert kinds(r) == [("region", "high", "a")]
    r = compare(boundary(res(rid="a")), [res(rid="a", region="eu-west-1")], regions={"us-east-1"})
    assert "outside the boundary's regions" in r.drifts[0].message


def test_global_resources_have_no_region_drift():
    b = boundary(res("AWS::IAM::Role", "r", region="us-east-1"))
    r = compare(b, [res("AWS::IAM::Role", "r", region="global"), res("AWS::IAM::User", "u", region="global")])
    assert kinds(r) == [("undeclared", "high", "u")]
    assert "outside" not in r.drifts[0].message


def test_undeclared_outside_account():
    r = compare(boundary(res(rid="a", account="1")), [res(rid="a", account="1"), res(rid="b", account="2")])
    assert "account 2, outside the boundary's accounts" in r.drifts[0].message


def test_encryption_rules():
    r = compare(boundary(res(rid="a"), res(rid="b"), res(rid="c", encrypted=False)),
                [res(rid="a", encrypted=False), res(rid="b"), res(rid="c", encrypted=False)], expect_encrypted=True)  # fmt: skip
    assert kinds(r) == [("encryption", "high", "a"), ("unverified", "info", "b")]
    assert r.drifts[1].control == ""


def test_public_rules():
    b = boundary(res(rid="a"), res(rid="b"), res(rid="c", public=True), expect_public=False)
    r = compare(b, [res(rid="a", public=True), res(rid="b"), res(rid="c", public=True)])
    assert kinds(r) == [("public", "critical", "a"), ("unverified", "info", "b")]
    assert r.drifts[0].control == "sc-7"


def test_boundary_wide_rules_skip_types_they_cannot_see():
    b = boundary(res("AWS::KMS::Key", "k"), expect_encrypted=True, expect_public=False)
    assert compare(b, [res("AWS::KMS::Key", "k")]).drifts == []
    b = boundary(res("AWS::KMS::Key", "k", public=False))  # an explicit per-resource rule still applies
    assert kinds(compare(b, [res("AWS::KMS::Key", "k")])) == [("unverified", "info", "k")]


def test_ignored_types_unless_declared():
    actual = [res("AWS::Config::ResourceCompliance", "x"), res("AWS::EC2::NetworkInterface", "eni-1")]
    r = compare(boundary(ignore_types={"AWS::EC2::NetworkInterface"}), actual)
    assert r.actual_count == 0 and sum(r.ignored.values()) == 2
    r = compare(boundary(res("AWS::Config::ResourceCompliance", "x")), actual[:1])
    assert r.actual_count == 1 and r.drifts == []


def test_gate():
    r = compare(boundary(res(rid="a")), [])
    assert r.failed(Severity.MEDIUM) and not r.failed(Severity.HIGH) and not r.failed(None)


def test_regions_derived_note():
    r = compare(boundary(res(rid="a", region="us-east-1")), [res(rid="a", region="us-east-1")])
    assert r.allowed_regions == {"us-east-1"} and "taken from the declared resources" in r.notes[0]


@pytest.mark.parametrize("value", ["CRITICAL", " high "])
def test_severity_parse(value):
    assert Severity.parse(value).rank <= 1


def test_severity_parse_error():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("bad")
