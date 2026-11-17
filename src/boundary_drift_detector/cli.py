"""Command-line interface.

    boundary-drift-detector check --declared ssp.json --actual config-export.json -o out --fail-on high
    boundary-drift-detector check --declared boundary.yaml --aws --aws-region us-east-1

Exit codes: 0 = no drift at or above --fail-on, 1 = drift at or above it, 2 = bad input.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from boundary_drift_detector import __version__
from boundary_drift_detector.actual import load_actual
from boundary_drift_detector.compare import compare
from boundary_drift_detector.declared import InputError, load_boundary
from boundary_drift_detector.model import Severity
from boundary_drift_detector.oscal import to_oscal
from boundary_drift_detector.report import to_json, to_markdown


def _severity(value: str) -> Severity | None:
    if value.lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _bool(value: str) -> bool:
    if value.lower() in ("true", "yes"):
        return True
    if value.lower() in ("false", "no"):
        return False
    raise argparse.ArgumentTypeError("use true or false")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="boundary-drift-detector",
        description="Compare a declared authorization boundary with what actually exists in AWS.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check", help="compare the boundary with an inventory")
    c.add_argument("--declared", required=True, help="OSCAL SSP (JSON) or boundary YAML")
    src = c.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--actual",
        action="append",
        help="AWS Config export or Terraform state (JSON); repeatable",
    )
    src.add_argument(
        "--aws",
        action="store_true",
        help="read the inventory live from AWS Config (needs boto3)",
    )
    c.add_argument("--aws-region", help="region for the AWS Config API call")
    c.add_argument("--aws-profile", help="AWS CLI profile to use")
    c.add_argument("--aggregator", help="AWS Config aggregator name (multi-account / multi-region)")
    c.add_argument(
        "--region",
        action="append",
        dest="regions",
        help="allowed region; repeatable (overrides the file)",
    )
    c.add_argument(
        "--account",
        action="append",
        dest="accounts",
        help="allowed account ID; repeatable",
    )
    c.add_argument(
        "--expect-encrypted",
        type=_bool,
        help="every applicable resource must be encrypted (true/false)",
    )
    c.add_argument(
        "--expect-public",
        type=_bool,
        help="whether applicable resources may be public (true/false)",
    )
    c.add_argument("-o", "--out-dir", help="write drift-report.{md,json} and drift.oscal.json here")
    c.add_argument(
        "--fail-on",
        type=_severity,
        default=None,
        metavar="SEVERITY",
        help="exit 1 if any drift is at or above: critical, high, medium, low, info, none (default none)",
    )
    c.add_argument("--timestamp", help=argparse.SUPPRESS)  # fixed time for reproducible samples
    return p


def run(args: argparse.Namespace, client=None) -> int:
    boundary = load_boundary(args.declared)
    if args.aws:
        from boundary_drift_detector.live import collect, make_client

        client = client or make_client(args.aws_region, args.aws_profile)
        actual = collect(client, aggregator=args.aggregator)
        sources = ["AWS Config (live" + (f", aggregator {args.aggregator}" if args.aggregator else "") + ")"]
    else:
        actual, sources = [], []
        for path in args.actual:
            resources, fmt, skipped = load_actual(path)
            actual += resources
            extra = f", {skipped} helper resources not compared" if skipped else ""
            sources.append(f"{Path(path).name} ({fmt}{extra})")
    report = compare(
        boundary,
        actual,
        actual_sources=sources,
        regions=set(args.regions or []),
        accounts=set(args.accounts or []),
        expect_encrypted=args.expect_encrypted,
        expect_public=args.expect_public,
    )
    timestamp = args.timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    sev = report.severity_counts()
    real = [d for d in report.drifts if d.kind != "unverified"]
    print(
        f"{boundary.name}: {len(real)} drift finding(s) "
        f"(critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']}); "
        f"{len(report.matches)}/{report.declared_count} declared resources matched, "
        f"{report.actual_count} in the inventory"
    )
    for d in report.drifts:
        if d.severity.rank <= Severity.HIGH.rank:
            r = d.resource
            print(f"  {d.severity.value.upper():8} {d.kind:<10} {r.type} {r.arn or r.id}: {d.message}")
    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        files = {
            "drift-report.md": to_markdown(report, as_of=timestamp),
            "drift-report.json": to_json(report, as_of=timestamp),
            "drift.oscal.json": json.dumps(to_oscal(report, timestamp=timestamp), indent=2) + "\n",
        }
        for name, text in files.items():
            (out / name).write_text(text, encoding="utf-8")
            print(f"wrote {out / name}")
    if report.failed(args.fail_on):
        print(f"gate: drift at or above '{args.fail_on.value}'", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None, client=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with contextlib.suppress(ValueError, OSError):
                stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return run(args, client=client)
    except (InputError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
