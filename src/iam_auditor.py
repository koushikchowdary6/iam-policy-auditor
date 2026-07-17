#!/usr/bin/env python3
"""IAM Policy Auditor.

Reads an AWS IAM policy document (JSON) and reports risky statements:
overly-broad wildcards, known privilege-escalation actions, public exposure,
and missing conditions on sensitive actions. Runs fully offline -- it analyzes
policy JSON you provide, so it needs no AWS credentials and touches no live
account.

Each finding has a severity (HIGH / MEDIUM / LOW), the offending statement,
and a plain-English explanation of the risk.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any

# A small, well-known set of IAM actions that enable privilege escalation
# (e.g. rewriting policies, creating access keys for other users). Not
# exhaustive -- a starting set drawn from widely documented escalation paths.
PRIV_ESC_ACTIONS = {
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:creategrouppolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:passrole",
    "sts:assumerole",
}

SENSITIVE_SERVICES = {"iam", "kms", "s3", "sts", "secretsmanager", "ec2"}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    statement_index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "statement_index": self.statement_index,
        }


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.findings:
            return "NONE"
        return max(self.findings, key=lambda f: order[f.severity]).severity

    def counts(self) -> dict[str, int]:
        c = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            c[f.severity] += 1
        return c


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def audit_statement(stmt: dict[str, Any], index: int) -> list[Finding]:
    findings: list[Finding] = []
    if stmt.get("Effect") != "Allow":
        return findings  # Deny statements reduce risk; we focus on Allow.

    actions = [a.lower() for a in _as_list(stmt.get("Action"))]
    resources = _as_list(stmt.get("Resource"))
    has_condition = bool(stmt.get("Condition"))
    principal = stmt.get("Principal")

    # 1. Action:* on Resource:* -- effectively admin.
    if "*" in actions and "*" in resources:
        findings.append(Finding(
            "HIGH", "Full administrative wildcard",
            "Statement allows Action '*' on Resource '*' -- this grants "
            "effectively unlimited permissions. Scope actions and resources "
            "to the minimum required.",
            index))
    else:
        # 2. Wildcard actions (service:* or *) short of full admin.
        if any(a == "*" or a.endswith(":*") for a in actions):
            findings.append(Finding(
                "MEDIUM", "Wildcard action",
                "Statement uses a wildcard action (e.g. 's3:*'). Prefer "
                "explicit actions so new, possibly dangerous actions aren't "
                "granted automatically.",
                index))
        # 3. Wildcard resource on sensitive services.
        if "*" in resources:
            services = {a.split(":")[0] for a in actions if ":" in a}
            if services & SENSITIVE_SERVICES:
                findings.append(Finding(
                    "MEDIUM", "Wildcard resource on sensitive service",
                    f"Resource '*' used with sensitive service(s) "
                    f"{sorted(services & SENSITIVE_SERVICES)}. Restrict to "
                    "specific ARNs.",
                    index))

    # 4. Privilege-escalation actions.
    esc = sorted(a for a in actions if a in PRIV_ESC_ACTIONS)
    if esc:
        findings.append(Finding(
            "HIGH", "Privilege-escalation action",
            f"Statement allows action(s) {esc} commonly used to escalate "
            "privileges (rewriting policies, creating credentials, assuming "
            "roles). Guard these with tight resources and conditions.",
            index))

    # 5. Public principal (resource-based policy exposed to everyone).
    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
        sev = "HIGH" if not has_condition else "MEDIUM"
        findings.append(Finding(
            sev, "Public principal",
            "Principal '*' exposes this resource to every AWS account/anonymous "
            "callers" + (" (a Condition is present, which may limit this)."
                         if has_condition else " with no Condition to limit access."),
            index))

    # 6. Sensitive wildcard action without any condition.
    if any(a == "*" or a.endswith(":*") for a in actions) and not has_condition:
        findings.append(Finding(
            "LOW", "Wildcard action without conditions",
            "A wildcard action has no Condition block (e.g. MFA, source IP, "
            "or tag constraints). Conditions add defense in depth.",
            index))

    return findings


def audit_policy(policy: dict[str, Any]) -> AuditReport:
    report = AuditReport()
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for i, stmt in enumerate(statements):
        report.findings.extend(audit_statement(stmt, i))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an AWS IAM policy JSON for risky permissions")
    parser.add_argument("policy_file", help="path to a policy JSON file, or '-' for stdin")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW"], default=None,
                        help="exit non-zero if any finding at/above this severity exists")
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.policy_file == "-" else open(args.policy_file).read()
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: not valid JSON: {exc}", file=sys.stderr)
        return 2

    report = audit_policy(policy)

    if args.json:
        print(json.dumps({
            "highest_severity": report.highest_severity,
            "counts": report.counts(),
            "findings": [f.to_dict() for f in report.findings],
        }, indent=2))
    else:
        if not report.findings:
            print("No risky statements found. ✅")
        else:
            counts = report.counts()
            print(f"IAM Policy Audit — {counts['HIGH']} HIGH, "
                  f"{counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW\n")
            for f in report.findings:
                print(f"[{f.severity}] {f.title} (statement #{f.statement_index})")
                print(f"    {f.detail}\n")

    if args.fail_on:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        if order[report.highest_severity] >= order[args.fail_on]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
