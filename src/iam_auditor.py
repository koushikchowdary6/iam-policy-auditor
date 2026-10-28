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
import math
import re
import sys
import unicodedata
from fnmatch import fnmatchcase
from ipaddress import collapse_addresses, ip_network
from dataclasses import dataclass, field
from typing import Any

PRIV_ESC_ACTIONS = {
    "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachuserpolicy",
    "iam:attachrolepolicy", "iam:attachgrouppolicy", "iam:putuserpolicy",
    "iam:putrolepolicy", "iam:creategrouppolicy", "iam:createaccesskey",
    "iam:createloginprofile", "iam:updateloginprofile", "iam:passrole",
    "sts:assumerole",
}
SENSITIVE_SERVICES = {"iam", "kms", "s3", "sts", "secretsmanager", "ec2"}

# IAM policy grammar: a misspelled security-relevant key must not be ignored
# and accidentally produce a clean audit. These are document keys, not
# arbitrary metadata fields; reject unknown keys before evaluating findings.
POLICY_KEYS = {"Version", "Id", "Statement"}
STATEMENT_KEYS = {
    "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
    "Resource", "NotResource", "Condition",
}
SUPPORTED_POLICY_VERSIONS = {"2008-10-17", "2012-10-17"}


def _unsafe_identifier_character(char: str) -> bool:
    """Catch invisible, bidi, and non-UTF-8 characters in IAM identifiers.

    C0-only checks miss bidirectional overrides and zero-width format marks,
    which can make a policy look different to a reviewer than it is to a
    parser. Preserve ordinary non-ASCII letters and combining accents.
    """
    category = unicodedata.category(char)
    return (
        category in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        or char == "\u034f"  # Combining grapheme joiner
        or "\ufe00" <= char <= "\ufe0f"
        or "\U000e0100" <= char <= "\U000e01ef"
    )


def _valid_policy_label(value: Any) -> bool:
    """Require visible, unpadded reviewer-facing IAM identifiers."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and value == value.strip()
        # A string of combining marks has no independently visible glyph.
        # Preserve combining accents attached to actual letters, though.
        and any(not unicodedata.category(char).startswith("M") for char in value)
        and not any(_unsafe_identifier_character(char) for char in value)
    )


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    statement_index: int

    def to_dict(self) -> dict[str, Any]:
        return {"severity": self.severity, "title": self.title, "detail": self.detail,
                "statement_index": self.statement_index}


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
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


def _as_list(value: Any) -> list[str]:
    """Normalize IAM string-or-string-array fields, rejecting malformed JSON."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ValueError("Action, NotAction, and Resource must be strings or arrays of strings")


def _is_public_principal(principal: Any) -> bool:
    """Return True when a Principal grants access to everyone.

    AWS accepts Principal values as strings, lists, or dictionaries whose
    values may themselves be lists. Treat a wildcard in any principal value
    as public instead of only recognizing {"AWS": "*"}.
    """
    if principal == "*":
        return True
    if isinstance(principal, list):
        return any(_is_public_principal(item) for item in principal)
    if isinstance(principal, dict):
        return any(_is_public_principal(value) for value in principal.values())
    return False


def _validate_principal(principal: Any, index: int, field_name: str) -> None:
    """Reject malformed principal shapes instead of reporting a clean policy.

    A principal is a non-empty string/list or a mapping from principal type
    (AWS, Service, Federated, CanonicalUser) to non-empty strings/lists.
    Nested mappings, empty alternatives and non-string values are invalid.
    """
    def valid_identifier(value: Any) -> bool:
        # AWS permits the entire Principal to be "*", but does not support
        # partial wildcards inside a principal name or ARN. A pattern such as
        # arn:aws:iam::123456789012:role/Admin* must not look like a concrete
        # principal and produce a misleading clean audit.
        return (_valid_policy_label(value)
                and (value == "*" or not any(char in value for char in "*?")))

    def valid_values(value: Any) -> bool:
        # A padded or visually spoofed wildcard is not the public "*" token.
        if isinstance(value, str):
            return valid_identifier(value)
        return (isinstance(value, list) and bool(value)
                and all(valid_identifier(item) for item in value))

    if isinstance(principal, dict):
        # IAM supports exactly these Principal/NotPrincipal mapping keys.
        # Unknown keys are not meaningful restrictions and must not pass
        # validation as if they represented legitimate AWS principals.
        allowed_types = {"AWS", "Service", "Federated", "CanonicalUser"}
        valid = bool(principal) and all(
            key in allowed_types and valid_values(value)
            for key, value in principal.items()
        )
    else:
        valid = valid_values(principal)
    if not valid:
        raise ValueError(f"Statement #{index}: {field_name} has invalid principal values")


def _concrete_principal_boundary(context_key: str, value: Any) -> bool:
    """Only recognizable fixed AWS identifiers narrow a public principal.

    A non-wildcard string is not necessarily a real account, organization,
    VPC, or endpoint boundary. Treat arbitrary values as unproven rather
    than downgrading a public grant on malformed or self-referential input.
    This is a conservative shape check, not an AWS resource lookup.
    """
    if not isinstance(value, str) or any(c in value for c in "*?") or "${" in value:
        return False
    patterns = {
        "aws:principalaccount": r"[0-9]{12}",
        "aws:principalorgid": r"o-[A-Za-z0-9]+",
        "aws:sourcevpc": r"vpc-[A-Fa-f0-9]+",
        "aws:sourcevpce": r"vpce-[A-Fa-f0-9]+",
    }
    return bool(re.fullmatch(patterns[context_key], value))


def _fixed_account_principal_arn(value: Any) -> bool:
    """Recognize an IAM principal ARN scoped to one concrete AWS account.

    A six-part string with a 12-digit fifth field is not necessarily an IAM
    principal. Reject other services, non-IAM regions, missing resources and
    malformed role/user paths before reducing public-access severity.
    This is shape validation, not an AWS identity lookup.
    """
    if not isinstance(value, str) or "${" in value:
        return False
    return bool(re.fullmatch(
        r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:"
        r"(?:root|(?:role|user)/[A-Za-z0-9+=,.@_*/?-]+)",
        value,
    ))


def _valid_condition_identifier(value: Any) -> bool:
    """Reject visually deceptive IAM condition operators and context keys.

    Tag context keys may legitimately contain ordinary ASCII spaces, but
    invisible controls and Unicode lookalike spaces make policy review
    ambiguous. Reject these before evaluating principal scoping.
    """
    return (
        _valid_policy_label(value)
        and not any(
            unicodedata.category(char) == "Zs" and char != " "
            for char in value
        )
    )


def _valid_condition_value(value: Any) -> bool:
    """Keep IAM Condition string values readable without changing tag semantics.

    Unlike context keys, tag values may legitimately contain ordinary ASCII
    spaces, including at their edges. Reject hidden format controls, surrogates,
    deceptive Unicode spaces, and strings made only of combining marks.
    """
    if not isinstance(value, str):
        return True
    return (
        bool(value.strip())
        and any(
            not char.isspace() and not unicodedata.category(char).startswith("M")
            for char in value
        )
        and not any(
            _unsafe_identifier_character(char)
            or (unicodedata.category(char) == "Zs" and char != " ")
            for char in value
        )
    )


def _condition_scopes_public_principal(condition: Any) -> bool:
    """Validate IAM Condition structure and recognize *positive* access scoping.

    TLS/MFA requirements can improve security but do not restrict the set of
    principals admitted by Principal '*'. Negative operators and IfExists
    clauses also cannot be treated as positive access restrictions.
    """
    if not isinstance(condition, dict) or not condition:
        raise ValueError("Condition must be a non-empty object of operators")
    scoped = False
    for operator, entries in condition.items():
        if not _valid_condition_identifier(operator):
            raise ValueError("Condition operators must be visible, unpadded strings")
        if not isinstance(entries, dict) or not entries:
            raise ValueError(f"Condition {operator}: must contain context keys")
        for key, value in entries.items():
            if not _valid_condition_identifier(key):
                raise ValueError(f"Condition {operator}: invalid context key")
            values = value if isinstance(value, list) else [value]
            if not values or any(
                not isinstance(v, (str, int, float, bool))
                or not _valid_condition_value(v)
                or (isinstance(v, float) and not math.isfinite(v))
                for v in values
            ):
                raise ValueError(f"Condition {operator}/{key}: invalid values")
            op, context_key = operator.lower(), key.lower()
            if op == "ipaddress" and context_key == "aws:sourceip":
                # Multiple CIDRs are OR-ed by IAM. Two /1 networks can cover
                # an entire address family even though neither is a /0.
                # Collapse the union per IP version before treating it as
                # a meaningful network restriction.
                # SourceIp is an IP-address condition, not a numeric or
                # arbitrary string comparison. Converting an integer with
                # str() can turn invalid IAM JSON into a plausible /32 and
                # incorrectly downgrade a public principal's severity.
                if any(not isinstance(value, str) for value in values):
                    raise ValueError("Condition IpAddress/aws:SourceIp requires CIDR strings")
                try:
                    networks = [ip_network(value, strict=False) for value in values]
                except ValueError as exc:
                    # A typo or malformed CIDR must not silently produce a
                    # reassuring audit result, even on a Deny statement.
                    raise ValueError("Condition IpAddress/aws:SourceIp has invalid CIDR") from exc
                restricted = all(
                    all(net.prefixlen > 0 for net in collapse_addresses(
                        n for n in networks if n.version == version
                    ))
                    for version in (4, 6)
                )
                scoped = scoped or restricted
            elif op in ("stringequals", "stringlike") and context_key in {
                "aws:principalorgid", "aws:principalaccount",
                "aws:sourcevpc", "aws:sourcevpce",
            }:
                # A wildcard pattern is not a concrete organization, account,
                # or network boundary; do not downgrade public access for it.
                # IAM policy variables (for example
                # aws:PrincipalAccount == ${aws:PrincipalAccount}) are not
                # fixed boundaries: self-comparisons can be tautologies.
                # Do not downgrade a public grant unless every alternative
                # is a concrete, non-wildcard value.
                scoped = scoped or all(
                    _concrete_principal_boundary(context_key, v) for v in values
                )
            elif op in ("arnequals", "arnlike") and context_key == "aws:principalarn":
                # An ARN may legitimately wildcard role names *within one
                # fixed AWS account*. Requiring a concrete 12-digit account
                # prevents arn:aws:iam::*:role/* from being treated as scoped.
                scoped = scoped or all(_fixed_account_principal_arn(v) for v in values)
    return scoped


def _has_action_pattern(action: str) -> bool:
    """AWS IAM Action supports glob-style * and ? within action names."""
    return "*" in action or "?" in action


def _is_broad_resource_arn(resource: str) -> bool:
    """Identify wildcards that span accounts, regions, or resource identities.

    A scoped path such as arn:aws:s3:::reports/2026/* is a common,
    legitimate least-privilege pattern. By contrast, a wildcard in the
    bucket name, account ID, region, or leading ARN resource selector can
    match entirely different resources and deserves a finding.
    This is a heuristic, not a full IAM authorization simulator.
    """
    parts = resource.split(":", 5)
    if len(parts) != 6 or parts[0].lower() != "arn":
        return False
    _, _, service, region, account, identifier = parts
    if not service or not identifier:
        return False
    if any(char in region or char in account for char in "*?"):
        return True
    # S3 ARNs identify a bucket before the first slash; wildcard object
    # prefixes under a fixed bucket are commonly intentional. For IAM roles,
    # policies, KMS keys and EC2 instances, however, the portion after
    # "role/", "key/" or "instance/" *is* the resource identity. Ignoring it
    # would miss role/Admin*, key/* and instance/i-* grants entirely.
    identity = (
        identifier.split("/", 1)[0].split(":", 1)[0]
        if service.lower() == "s3"
        else identifier
    )
    return any(char in identity for char in "*?")


def _privilege_escalation_matches(actions: list[str]) -> list[str]:
    """Return known escalation actions granted by exact or glob Action entries.

    IAM action names are case-insensitive and normalized to lowercase before
    this helper is called. A global '*' is handled separately as full admin to
    avoid producing a noisy duplicate finding for every known escalation path.
    """
    matched: set[str] = set()
    for pattern in actions:
        if pattern == "*":
            continue
        matched.update(
            candidate for candidate in PRIV_ESC_ACTIONS
            if fnmatchcase(candidate, pattern)
        )
    return sorted(matched)


def audit_statement(stmt: dict[str, Any], index: int) -> list[Finding]:
    # Direct Python callers can supply non-string mapping keys even though
    # JSON documents cannot. Reject them before sorting unsupported names:
    # mixed str/int keys otherwise raise TypeError instead of a policy error.
    if not isinstance(stmt, dict) or any(not isinstance(key, str) for key in stmt):
        raise ValueError(f"Statement #{index}: keys must be strings")
    unknown = set(stmt) - STATEMENT_KEYS
    if unknown:
        raise ValueError(f"Statement #{index}: unsupported keys: {', '.join(sorted(unknown))}")
    # Optional statement IDs must be meaningful, not arbitrary JSON values.
    if "Sid" in stmt and not _valid_policy_label(stmt["Sid"]):
        raise ValueError(f"Statement #{index}: Sid must be non-empty text without controls")
    # Reject malformed policy statements instead of silently reporting no risk.
    effect = stmt.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise ValueError(f"Statement #{index}: Effect must be Allow or Deny")
    # AWS only supports NotPrincipal with Deny. Ignoring an unsupported
    # Allow/NotPrincipal statement could otherwise produce a misleading
    # "No risky statements found" audit result.
    if "NotPrincipal" in stmt:
        if "Principal" in stmt:
            raise ValueError(f"Statement #{index}: Principal and NotPrincipal are mutually exclusive")
        if effect != "Deny":
            raise ValueError(f"Statement #{index}: NotPrincipal requires Effect Deny")
    for principal_field in ("Principal", "NotPrincipal"):
        if principal_field in stmt:
            _validate_principal(stmt[principal_field], index, principal_field)
    if ("Action" in stmt) == ("NotAction" in stmt):
        raise ValueError(f"Statement #{index}: exactly one of Action/NotAction is required")
    if ("Resource" in stmt) == ("NotResource" in stmt):
        raise ValueError(f"Statement #{index}: exactly one of Resource/NotResource is required")
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        if key in stmt and (not _as_list(stmt[key]) or any(not v.strip() for v in _as_list(stmt[key]))):
            raise ValueError(f"Statement #{index}: {key} must contain non-empty strings")

    # A padded wildcard such as "* " is not an IAM Resource wildcard.
    # Reject ambiguous/control-bearing resource identifiers before analysis,
    # rather than returning a false clean result for malformed input.
    for resource_key in ("Resource", "NotResource"):
        if resource_key in stmt:
            for resource in _as_list(stmt[resource_key]):
                if not _valid_policy_label(resource):
                    raise ValueError(
                        f"Statement #{index}: {resource_key} contains an invalid resource identifier"
                    )

    # A misspelled action must not silently look like a harmless permission.
    # IAM actions are either '*' or service:operation glob patterns. Reject
    # spaces, missing separators, extra colons and control characters.
    for action_key in ("Action", "NotAction"):
        if action_key in stmt:
            for action in _as_list(stmt[action_key]):
                if action != "*" and not re.fullmatch(r"[A-Za-z0-9*?-]+:[A-Za-z0-9*?-]+", action):
                    raise ValueError(f"Statement #{index}: {action_key} has invalid action identifier {action!r}")

    # Validate conditions even on Deny statements. A malformed Condition
    # must not cause a public grant to be reported as conditionally restricted.
    condition = stmt.get("Condition")
    scopes_public_principal = (
        _condition_scopes_public_principal(condition)
        if "Condition" in stmt else False
    )

    findings: list[Finding] = []
    if effect == "Deny":
        return findings

    actions = [a.lower() for a in _as_list(stmt.get("Action"))]
    not_actions = [a.lower() for a in _as_list(stmt.get("NotAction"))]
    resources = _as_list(stmt.get("Resource"))
    not_resources = _as_list(stmt.get("NotResource"))
    # NotResource excludes only named ARNs; a service-wide wildcard still
    # grants every action in that service on all other resources. A global
    # action wildcard is not the only dangerous combination.
    service_wildcard = any(a.endswith(":*") for a in actions)
    if not_resources and ("*" in actions or service_wildcard or not_actions):
        findings.append(Finding(
            "HIGH", "Broad NotResource allow",
            "Allow with NotResource excludes only the listed resources; combined "
            "with a global action or NotAction it can grant broad access to "
            "other resources. Prefer explicit least-privilege Resource ARNs.",
            index))
    elif not_resources:
        # Even a single named action applies to every resource except those
        # excluded. Omitting this finding made broad resource exposure appear
        # clean whenever the action selector itself was narrow.
        findings.append(Finding(
            "MEDIUM", "NotResource expands resource scope",
            "Allow with NotResource grants the listed actions on every resource "
            "except the excluded ARNs. This is not a resource allow-list; "
            "prefer explicit Resource ARNs to limit the blast radius.",
            index))
    has_condition = "Condition" in stmt
    principal = stmt.get("Principal")

    # Allow + NotAction means "allow everything except ...". On Resource '*'
    # this is easy to mistake for a narrow deny-list while actually granting a
    # very broad capability set, so surface it prominently.
    if not_actions:
        severity = "HIGH" if "*" in resources else "MEDIUM"
        findings.append(Finding(
            severity, "Broad NotAction allow",
            "Allow with NotAction grants every action except the exclusions "
            f"{not_actions}. Prefer an explicit Action allow-list; review the "
            "resource scope carefully because new AWS actions may become allowed "
            "without a policy change.", index))

    if "*" in actions and "*" in resources:
        findings.append(Finding(
            "HIGH", "Full administrative wildcard",
            "Statement allows Action '*' on Resource '*' -- this grants effectively "
            "unlimited permissions. Scope actions and resources to the minimum required.",
            index))
    else:
        if any(_has_action_pattern(a) for a in actions):
            findings.append(Finding(
                "MEDIUM", "Wildcard action",
                "Statement uses a wildcard action (e.g. 's3:Get*' or 'iam:PassR?le'). Prefer explicit "
                "actions so new, possibly dangerous actions aren't granted automatically.",
                index))
        if "*" in resources:
            services = {a.split(":")[0] for a in actions if ":" in a}
            if services & SENSITIVE_SERVICES:
                findings.append(Finding(
                    "MEDIUM", "Wildcard resource on sensitive service",
                    f"Resource '*' used with sensitive service(s) "
                    f"{sorted(services & SENSITIVE_SERVICES)}. Restrict to specific ARNs.",
                    index))

    # Resource '*' is covered above, but wildcard ARN account IDs and
    # resource identities can be just as broad while appearing scoped.
    # Avoid flagging a wildcard *inside* a named resource's path.
    if (any(_is_broad_resource_arn(resource) for resource in resources)
            and ("*" in actions or any(
                action.split(":", 1)[0] in SENSITIVE_SERVICES for action in actions
            ))):
        findings.append(Finding(
            "MEDIUM", "Broad resource ARN pattern",
            "A wildcard in an ARN account, region, or resource identity can "
            "grant access beyond a named resource. Scope the ARN to the "
            "intended account and resource identifiers.", index))

    esc = _privilege_escalation_matches(actions)
    if esc:
        findings.append(Finding(
            "HIGH", "Privilege-escalation action",
            f"Statement grants action(s) {esc} commonly used to escalate privileges "
            "(including grants reached through IAM Action wildcards). Guard these "
            "with tight resources and conditions.", index))

    if _is_public_principal(principal):
        # A TLS-only or MFA-only Condition does not make Principal '*'
        # private; downgrade only for a recognized positive network/principal
        # scope. This is heuristic risk analysis, not IAM policy simulation.
        sev = "MEDIUM" if scopes_public_principal else "HIGH"
        findings.append(Finding(
            sev, "Public principal",
            "Principal '*' exposes this resource to every AWS account/anonymous callers" +
            (" (a positive network/principal scoping Condition is present; verify its scope)."
             if scopes_public_principal
             else " (no recognized positive principal/network restriction)."), index))

    if any(_has_action_pattern(a) for a in actions) and not has_condition:
        findings.append(Finding(
            "LOW", "Wildcard action without conditions",
            "A wildcard action has no Condition block (e.g. MFA, source IP, or tag "
            "constraints). Conditions add defense in depth.", index))

    return findings


def audit_policy(policy: dict[str, Any]) -> AuditReport:
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    if any(not isinstance(key, str) for key in policy):
        raise ValueError("Policy keys must be strings")
    unknown = set(policy) - POLICY_KEYS
    if unknown:
        raise ValueError(f"Policy has unsupported keys: {', '.join(sorted(unknown))}")
    if "Version" in policy and (
        not isinstance(policy["Version"], str)
        or policy["Version"] not in SUPPORTED_POLICY_VERSIONS
    ):
        raise ValueError("Version must be 2008-10-17 or 2012-10-17")
    if "Id" in policy and not _valid_policy_label(policy["Id"]):
        raise ValueError("Id must be non-empty text without controls")
    # A missing or empty Statement is not a valid IAM policy. Reporting it as
    # "No risky statements found" could give a false assurance of safety.
    if "Statement" not in policy:
        raise ValueError("Statement is required")
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError("Statement must be a non-empty object or list of objects")

    report = AuditReport()
    for i, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            raise ValueError(f"Statement #{i} must be an object")
        report.findings.extend(audit_statement(stmt, i))
    return report


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous policy JSON instead of silently accepting last-key-wins.

    Python's default json.loads behavior can turn an Allow into a Deny (or
    replace a dangerous Action) when an attacker supplies duplicate keys.
    Auditing the resulting dictionary would falsely report a clean policy.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    """Disallow NaN/Infinity; AWS policy documents require standard JSON."""
    raise ValueError(f"non-standard JSON value: {value}")


def parse_policy_json(raw: str) -> dict[str, Any]:
    """Parse strict JSON before performing the IAM policy audit."""
    return json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_nonstandard_json_constant,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an AWS IAM policy JSON for risky permissions")
    parser.add_argument("policy_file", help="path to a policy JSON file, or '-' for stdin")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW"], default=None,
                        help="exit non-zero if any finding at/above this severity exists")
    args = parser.parse_args(argv)

    try:
        if args.policy_file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.policy_file, encoding="utf-8") as handle:
                raw = handle.read()
        policy = parse_policy_json(raw)
        report = audit_policy(policy)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"highest_severity": report.highest_severity,
                          "counts": report.counts(),
                          "findings": [f.to_dict() for f in report.findings]}, indent=2))
    elif not report.findings:
        print("No risky statements found. ✅")
    else:
        counts = report.counts()
        print(f"IAM Policy Audit — {counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
              f"{counts['LOW']} LOW\n")
        for finding in report.findings:
            print(f"[{finding.severity}] {finding.title} (statement #{finding.statement_index})")
            print(f"    {finding.detail}\n")

    if args.fail_on:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        if order[report.highest_severity] >= order[args.fail_on]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
