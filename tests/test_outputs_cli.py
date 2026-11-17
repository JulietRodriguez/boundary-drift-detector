"""Reports, OSCAL output, live mode with a fake AWS client, and the CLI."""

import json
import subprocess
import sys

import pytest

from boundary_drift_detector.actual import load_actual
from boundary_drift_detector.cli import main
from boundary_drift_detector.compare import compare
from boundary_drift_detector.declared import load_boundary
from boundary_drift_detector.live import QUERY, collect
from boundary_drift_detector.oscal import to_oscal
from boundary_drift_detector.report import to_dict, to_markdown
from tests.conftest import ROOT, SAMPLES, SCHEMAS, FakeConfigClient

TS = "2026-11-17T12:00:00+00:00"


@pytest.fixture(scope="module")
def ssp_report():
    return compare(load_boundary(SAMPLES / "ssp.json"), load_actual(SAMPLES / "aws-config-export.json")[0],
                   actual_sources=["aws-config-export.json"])  # fmt: skip


def validate(doc, schema):
    from tools.validate_oscal import load_validator

    return [e.message for e in load_validator(SCHEMAS / schema).iter_errors(doc)]


# --- reports ------------------------------------------------------------------------------------


def test_json_report(ssp_report):
    d = to_dict(ssp_report, as_of=TS)
    assert d["drift_by_kind"]["undeclared"] == 2 and d["matched"] == 8
    assert d["match_methods"] == {"arn": 8, "id": 0, "name": 0}
    assert d["drifts"][0]["severity"] == "critical"
    assert d["inventory"]["ignored_by_type"] == {"AWS::Config::ResourceCompliance": 1}


def test_markdown_report(ssp_report):
    md = to_markdown(ssp_report, as_of=TS)
    assert "## Result: 5 drift finding(s)" in md
    assert "## Public exposure drift (1)" in md and "| SC-7 |" in md
    assert "## Unverified expectations (1)" in md and "| - |" in md
    assert "## What to do" in md


def test_markdown_clean_report():
    r = compare(load_boundary(SAMPLES / "boundary.yaml"), load_actual(SAMPLES / "terraform.tfstate")[0])
    assert "boundary matches the inventory" in to_markdown(r, as_of=TS)


# --- OSCAL --------------------------------------------------------------------------------------


def test_oscal_is_schema_valid_and_uses_ssp_inventory(ssp_report):
    doc = to_oscal(ssp_report, timestamp=TS)
    assert validate(doc, "oscal_assessment-results_schema.json") == []
    result = doc["assessment-results"]["results"][0]
    ssp_items = {i["uuid"] for i in json.loads((SAMPLES / "ssp.json").read_text())["system-security-plan"]
                 ["system-implementation"]["inventory-items"]}  # fmt: skip
    local = {i["uuid"] for i in result["local-definitions"]["inventory-items"]}
    subjects = {s["subject-uuid"] for o in result["observations"] for s in o["subjects"]}
    assert subjects <= ssp_items | local
    assert len(local) == 2  # the two undeclared resources
    findings = {f["target"]["target-id"]: f for f in result["findings"]}
    assert set(findings) == {"cm-8_obj", "sc-28_obj", "sc-7_obj"}  # unverified items make no finding
    assert {p["value"] for p in findings["cm-8_obj"]["props"]} == {"critical"}
    assert doc == to_oscal(ssp_report, timestamp=TS)


def test_oscal_clean_run_has_no_findings():
    r = compare(load_boundary(SAMPLES / "boundary.yaml"), load_actual(SAMPLES / "terraform.tfstate")[0])
    doc = to_oscal(r, timestamp=TS)
    result = doc["assessment-results"]["results"][0]
    assert "findings" not in result and "observations" not in result
    assert validate(doc, "oscal_assessment-results_schema.json") == []


def test_sample_ssp_is_schema_valid():
    assert validate(json.loads((SAMPLES / "ssp.json").read_text()), "oscal_ssp_schema.json") == []


# --- live mode (fake client) ---------------------------------------------------------------------


ITEMS = [
    {"arn": "arn:aws:s3:::cms-demo-case-files", "resourceType": "AWS::S3::Bucket", "resourceId": "cms-demo-case-files",
     "awsRegion": "us-east-1", "accountId": "111122223333", "configuration": {}, "supplementaryConfiguration": {}},
    {"arn": "arn:aws:s3:::other", "resourceType": "AWS::S3::Bucket", "resourceId": "other", "awsRegion": "us-east-1"},
    {"arn": "arn:aws:s3:::third", "resourceType": "AWS::S3::Bucket", "resourceId": "third", "awsRegion": "us-east-1"},
]  # fmt: skip


def test_collect_pages_through_results():
    client = FakeConfigClient(ITEMS, page_size=2)
    resources = collect(client)
    assert [r.id for r in resources] == ["cms-demo-case-files", "other", "third"]
    assert len(client.calls) == 2 and client.calls[1]["NextToken"] == "2"
    assert client.calls[0]["Expression"] == QUERY


def test_collect_with_aggregator():
    client = FakeConfigClient(ITEMS[:1])
    collect(client, aggregator="org-agg")
    assert client.calls[0]["ConfigurationAggregatorName"] == "org-agg"


def test_cli_live_mode_with_fake_client(capsys):
    code = main(["check", "--declared", str(SAMPLES / "boundary.yaml"), "--aws", "--aggregator", "agg"],
                client=FakeConfigClient(ITEMS))  # fmt: skip
    out = capsys.readouterr().out
    assert code == 0 and "1/9 declared resources matched" in out


def test_make_client_needs_boto3(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert main(["check", "--declared", str(SAMPLES / "boundary.yaml"), "--aws"]) == 2


# --- CLI ---------------------------------------------------------------------------------------


def args(declared="ssp.json", actual="aws-config-export.json"):
    return ["check", "--declared", str(SAMPLES / declared), "--actual", str(SAMPLES / actual)]


def test_cli_writes_outputs(tmp_path, capsys):
    assert main([*args(), "-o", str(tmp_path), "--timestamp", TS]) == 0
    out = capsys.readouterr().out
    assert "5 drift finding(s) (critical 2, high 2, medium 1, low 0)" in out
    assert "CRITICAL undeclared" in out
    assert sorted(p.name for p in tmp_path.iterdir()) == ["drift-report.json", "drift-report.md", "drift.oscal.json"]


@pytest.mark.parametrize(("fail_on", "code"), [("critical", 1), ("high", 1), ("none", 0)])
def test_cli_gate(fail_on, code, capsys):
    assert main([*args(), "--fail-on", fail_on]) == code


def test_cli_clean_terraform_passes_strict_gate(tmp_path, capsys):
    assert main([*args("boundary.yaml", "terraform.tfstate"), "--fail-on", "low", "-o", str(tmp_path)]) == 0
    assert (
        "terraform.tfstate (terraform, 4 helper resources not compared)" in (tmp_path / "drift-report.md").read_text()
    )


def test_cli_overrides(capsys):
    code = main([*args("boundary.yaml", "terraform.tfstate"), "--region", "eu-west-1", "--account", "999",
                 "--expect-encrypted", "true", "--expect-public", "no", "--fail-on", "high"])  # fmt: skip
    assert code == 1 and "outside the boundary's regions" in capsys.readouterr().out


@pytest.mark.parametrize("bad", [["--fail-on", "severe"], ["--expect-public", "maybe"]])
def test_cli_bad_arguments(bad):
    with pytest.raises(SystemExit) as exc:
        main([*args(), *bad])
    assert exc.value.code == 2


def test_cli_input_error(tmp_path, capsys):
    assert main(["check", "--declared", str(tmp_path / "none.yaml"), "--actual", "x"]) == 2
    assert "error:" in capsys.readouterr().err


def test_module_entry_point():
    proc = subprocess.run([sys.executable, "-m", "boundary_drift_detector", "--version"], capture_output=True,
                          text=True, check=False, env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""})  # fmt: skip
    assert proc.returncode == 0 and "0.1.0" in proc.stdout


def test_samples_are_up_to_date():
    proc = subprocess.run([sys.executable, str(ROOT / "tools" / "make_samples.py"), "--check"], capture_output=True,
                          text=True, check=False)  # fmt: skip
    assert proc.returncode == 0, proc.stderr
