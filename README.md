# IAM Policy Auditor ☁️🔍

[![CI](https://github.com/koushikchowdary6/iam-policy-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/iam-policy-auditor/actions/workflows/ci.yml)

A static analyzer for **AWS IAM policies.** Point it at a policy JSON and it
reports risky permissions — wildcards, privilege-escalation actions, public
exposure, and missing conditions — each with a severity and a plain-English
explanation.

It runs **fully offline**: it analyzes the policy document you give it, so it
needs no AWS credentials and never touches a live account. That makes it safe
to drop into CI as a guardrail on policy changes.

## What it flags

| Check | Severity | Why it matters |
|---|---|---|
| `Action: "*"` on `Resource: "*"` | HIGH | Effectively account admin |
| Privilege-escalation actions (e.g. `iam:CreatePolicyVersion`, `iam:PassRole`, `sts:AssumeRole`) | HIGH | Lets a principal grant itself more access |
| `Principal: "*"` with no condition | HIGH | Resource exposed to every account / anonymous |
| Wildcard action (`s3:*`) | MEDIUM | Silently grants future/dangerous actions |
| Wildcard resource on a sensitive service (iam, kms, s3, sts…) | MEDIUM | Over-broad blast radius |
| Wildcard action with no `Condition` | LOW | Missing defense-in-depth (MFA, source IP, tags) |

## Usage

```bash
python src/iam_auditor.py examples/admin_wildcard.json
python src/iam_auditor.py policy.json --json          # machine-readable output
cat policy.json | python src/iam_auditor.py -         # read from stdin
python src/iam_auditor.py policy.json --fail-on HIGH   # exit 1 if any HIGH finding (for CI)
```

Example:

```
$ python src/iam_auditor.py examples/privilege_escalation.json
IAM Policy Audit — 1 HIGH, 0 MEDIUM, 0 LOW

[HIGH] Privilege-escalation action (statement #0)
    Statement allows action(s) ['iam:createpolicyversion', 'iam:setdefaultpolicyversion']
    commonly used to escalate privileges ...
```

## Use it as a CI guardrail

```yaml
- run: python src/iam_auditor.py my-policy.json --fail-on HIGH
```

The build fails if anyone introduces a HIGH-severity permission.

## Tests

```bash
pip install pytest && python -m pytest tests/ -v
```

## Scope & honesty

The privilege-escalation action list is a curated starting set drawn from
widely documented escalation paths — it is **not** exhaustive, and a clean
result is not a guarantee of a safe policy. This is a first-pass linter to
catch common mistakes, not a replacement for a full access review or tools
like AWS IAM Access Analyzer.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) · [GitHub](https://github.com/koushikchowdary6)
