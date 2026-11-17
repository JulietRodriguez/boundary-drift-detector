"""Validate OSCAL JSON against NIST's OSCAL 1.1.2 JSON schemas.

    python tools/validate_oscal.py --schema-dir schemas FILE [FILE ...]

The model (SSP or Assessment Results) is detected from the top-level key.
NIST's schemas use \\p{L} and \\p{N} in regex patterns, which Python's ``re``
doesn't support; those two classes are translated to [^\\W\\d_] and \\d first.
Every other keyword is used as published. Needs jsonschema.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft7Validator

SCHEMAS = {
    "system-security-plan": "oscal_ssp_schema.json",
    "assessment-results": "oscal_assessment-results_schema.json",
}
_REWRITES = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d"}


def _rewrite(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                for a, b in _REWRITES.items():
                    v = v.replace(a, b)
            out[k] = _rewrite(v)
        return out
    if isinstance(node, list):
        return [_rewrite(v) for v in node]
    return node


def load_validator(schema_path: Path) -> Draft7Validator:
    return Draft7Validator(_rewrite(json.loads(Path(schema_path).read_text(encoding="utf-8"))))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--schema-dir", required=True, type=Path)
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)
    failed = 0
    for f in args.files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        model = next((m for m in SCHEMAS if m in doc), None)
        if model is None:
            print(f"FAIL {f}: not an OSCAL SSP or Assessment Results")
            failed += 1
            continue
        errs = list(load_validator(args.schema_dir / SCHEMAS[model]).iter_errors(doc))
        if errs:
            failed += 1
            print(f"FAIL {f}: {len(errs)} error(s)")
            for e in errs[:20]:
                print(f"     {'/'.join(map(str, e.absolute_path))}: {e.message}")
        else:
            print(f"OK   {f}: valid OSCAL {model} per {SCHEMAS[model]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
