"""CLI: aion-security blue run <check> ...

Dry run by default: prints the run result as JSON and changes nothing.
--report sends the result to Runtime; --propose also submits remediation
proposals (pending human approval). Neither flag executes anything.

Exit codes: 0 pass, 1 fail (findings), 2 error (could not observe / report).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .blue import control_for, run_check
from .blue.checks import REGISTRY
from .connectors import FileIdentityConnector
from .contracts import RunStatus
from .runtime_client import RuntimeClient, RuntimeError_

EXIT = {RunStatus.PASS: 0, RunStatus.FAIL: 1, RunStatus.ERROR: 2}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aion-security")
    sub = p.add_subparsers(dest="team", required=True)
    blue = sub.add_parser("blue", help="Continuous Assurance runners")
    bsub = blue.add_subparsers(dest="cmd", required=True)

    run = bsub.add_parser("run", help="run one check")
    run.add_argument("check", choices=sorted(REGISTRY))
    run.add_argument("--idp-export", required=True, help="normalized IdP export JSON")
    run.add_argument("--controls", help="override path to controls.lock.json")
    run.add_argument("--runtime-url", default=os.environ.get("AION_RUNTIME_URL"))
    run.add_argument("--report", action="store_true", help="report the run to Runtime /v1/assurance")
    run.add_argument(
        "--propose",
        action="store_true",
        help="also submit remediation proposals to /v1/commands (pending human approval)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.propose:
        args.report = True

    control = control_for(args.check, args.controls)
    check = REGISTRY[args.check](FileIdentityConnector(args.idp_export))
    result = run_check(check, control)
    out = result.to_dict()

    if args.report:
        if not args.runtime_url:
            print("error: --report needs --runtime-url or AION_RUNTIME_URL", file=sys.stderr)
            return 2
        client = RuntimeClient(args.runtime_url, token=os.environ.get("AION_RUNTIME_TOKEN"))
        try:
            out["runtime"] = {"run": client.report_run(result)}
            if args.propose and result.status is RunStatus.FAIL:
                out["runtime"]["proposals"] = [client.propose(p, result) for p in result.proposals]
        except RuntimeError_ as e:
            print(json.dumps(out, indent=2))
            print(f"error: {e}", file=sys.stderr)
            return 2
    elif not control.pinned:
        print(
            f"note: control for {args.check!r} is UNPINNED; dry run only until pinned from aion-docs",
            file=sys.stderr,
        )

    print(json.dumps(out, indent=2))
    return EXIT[result.status]


if __name__ == "__main__":
    sys.exit(main())
