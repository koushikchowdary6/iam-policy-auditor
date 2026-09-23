# Threat Model

## Purpose

`iam-policy-auditor` is a static first-pass linter for AWS IAM policy JSON. It is designed to identify common high-risk authorization patterns before a policy reaches production or during code review.

## Assets the tool helps protect

- AWS identities and roles from unintended privilege escalation.
- Cloud resources from overly broad or public access.
- CI/CD pipelines from merging obviously dangerous policy changes.
- Reviewers from missing high-signal IAM mistakes in large JSON documents.

## Trust boundaries

The policy document is **untrusted input**. The analyzer does not require AWS credentials and does not make changes to a live AWS account. Findings are advisory output consumed by a developer, reviewer, or CI job.

The tool deliberately stays offline. This reduces credential exposure and makes scans deterministic, but it also means the analyzer cannot see account-specific context such as resource policies, SCPs, permission boundaries, identity-center assignments, or effective permissions.

## Threats covered

### Broad administrative access

Policies containing wildcard actions and resources can effectively grant administrator-level capabilities. These patterns receive high-severity findings.

### Privilege-escalation paths

The analyzer flags a curated set of actions commonly involved in escalation, including capabilities for changing policies, passing roles, or assuming roles.

### Public principals

Resource-style statements with unrestricted principals and no constraining condition are treated as high risk because they can expose a resource outside the intended trust boundary.

### Over-broad service permissions

Service-level wildcards and wildcard resources increase blast radius and can silently include permissions added by AWS later.

### Missing conditions

The absence of useful conditions can remove defense-in-depth controls such as source restrictions, MFA requirements, or tag-based constraints.

## Out of scope

A clean result does **not** prove that a policy is safe. The analyzer does not currently compute effective permissions across multiple policies, evaluate SCPs or permission boundaries, resolve every IAM condition operator, inspect a live AWS account, or exhaustively model every privilege-escalation technique.

For production authorization reviews, findings should be combined with AWS-native analysis, account context, least-privilege review, and testing.

## CI security model

`--fail-on HIGH` is intended as a guardrail, not a complete authorization gate. A CI pipeline can reject newly introduced high-severity patterns while still requiring human review for context-sensitive risks.
