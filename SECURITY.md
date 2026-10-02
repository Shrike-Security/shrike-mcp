# Security Policy

Shrike Security takes the security of our software products and services seriously. This document describes how to report security vulnerabilities and what to expect from us in return.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in `shrike-mcp` (this repository) or any other Shrike Security product, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

### Preferred reporting channel

Email: **security@shrikesecurity.com**

Encryption (optional but encouraged for sensitive reports):
- PGP key: [to be published at https://shrikesecurity.com/.well-known/security.txt]
- We accept reports in any human language; English is preferred for fastest triage.

### What to include in your report

To help us understand and address your report quickly, please include as much of the following as possible:

- Type of issue (e.g. injection, authentication bypass, sensitive data exposure, denial of service)
- Full paths of source files related to the manifestation of the issue
- Location of affected source code (tag/branch/commit + permalink, or specific URL)
- Step-by-step reproduction instructions
- Proof-of-concept or exploit code (if possible — please share privately, not publicly)
- Impact of the issue, including how an attacker might exploit it
- Whether you intend to publicly disclose this issue (and any constraints on timing)

This information will help us triage your report more quickly.

## Response Timeline

We commit to the following response timeline once we receive a report:

| Stage | Target |
|---|---|
| Initial acknowledgment | Within 2 business days |
| Initial assessment + triage | Within 5 business days |
| Fix released (for confirmed valid reports, severity-dependent) | Critical: 7 days · High: 30 days · Medium: 90 days · Low: best effort |
| Public disclosure | Coordinated with reporter, typically 30-90 days after fix release |

We will keep you informed throughout the process and will work with you on coordinated disclosure.

## Scope

### In scope

- This repository (`shrike-mcp`) — the Model Context Protocol server published as `shrike-mcp` on npm
- The Shrike Security backend API at `api.shrikesecurity.com` (the `/agent` endpoint and `/dashboard` endpoint families)
- Other Shrike-published packages: `shrike-guard` (Python/TypeScript SDKs), `shrike-webmcp` (browser SDK), Chrome browser extension
- Authentication and authorization mechanisms (API keys, JWT, OAuth flows)
- Data handling and storage practices

### Out of scope

- Findings from automated tools without a working proof-of-concept (we use these ourselves; please demonstrate real impact)
- Denial-of-service attacks against our test or production infrastructure (rate-limit by-design behavior is not a vulnerability)
- Social engineering of Shrike Security employees, advisors, or customers
- Physical attacks against Shrike Security infrastructure
- Issues in third-party dependencies that have not yet been disclosed by the upstream maintainer (please report upstream first; we will track via our dependency monitoring)
- Findings that require physical access to a user's device or local network
- Best-practice recommendations without a corresponding vulnerability (e.g., missing headers without demonstrated exploit)

## Coordinated Disclosure

We follow a coordinated disclosure model:

1. You report the vulnerability privately to security@shrikesecurity.com
2. We acknowledge receipt and begin investigation
3. We confirm or refute the vulnerability and develop a fix
4. We deploy the fix and notify affected customers as necessary
5. We coordinate a public disclosure timeline with you (typically 30-90 days after fix release)
6. We credit you in the security advisory unless you prefer to remain anonymous

We commit to:
- Not pursue legal action against researchers who report in good faith, comply with this policy, and avoid privacy violations, data destruction, or service degradation
- Work with you in good faith to understand and address the issue
- Credit you publicly (if desired) once the issue is resolved

## Safe Harbor

We support security research conducted in good faith. If you make a good-faith effort to comply with this policy during your security research, we will:

- Consider your research authorized under this policy
- Work with you to understand and resolve the issue quickly
- Not pursue or support any legal action related to your research
- Acknowledge your contribution publicly if you wish

If at any point you are uncertain whether your planned research is authorized, please contact us at security@shrikesecurity.com BEFORE proceeding.

## Acknowledgments

Researchers who have helped us improve the security of Shrike will be acknowledged here (with consent):

- _(no reports yet — be the first!)_

## Related Disclosures

For broader Shrike Security regulatory and compliance posture:
- NIST CAISI public comment on AI agent security: [Comment NIST-2025-0035-0074](https://www.regulations.gov/comment/NIST-2025-0035-0074)
- Compliance & Trust Center: https://shrikesecurity.com/compliance

## Policy History

| Version | Date | Notes |
|---|---|---|
| 1.0 | 2026-06-19 | Initial publication |
