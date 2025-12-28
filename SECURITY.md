# Security Policy

## Scope

This repository is an experimental fork intended for learning and protocol hardening experiments.
It has not been independently security-audited.

## Supported Versions

No versions are currently supported for production use.

## Reporting a Vulnerability

Please report security issues responsibly.

Preferred: Use GitHub Security Advisories (if enabled) for private reporting.
If private reporting is not available, contact the maintainer of this fork directly.

Please include:
- a clear description of the issue and where it occurs
- steps to reproduce (proof-of-concept if applicable)
- expected vs. actual behavior
- potential impact and threat model assumptions
- suggested mitigation (optional)

Please do not disclose vulnerabilities publicly until they have been reviewed and addressed.

## Security Considerations (Known Limitations)

This codebase implements custom protocol and cryptographic logic and may include limitations such as:

- lack of peer identity authentication (MITM risk depending on threat model)
- key derivation and key separation may be incomplete or evolving
- transport-level framing and message boundary handling over TCP may be incomplete or evolving
- limited replay/DoS protections
- no formal verification and no external audit

## Disclaimer
This software is provided "as is", without warranty of any kind.
Use at your own risk.

This software is provided "as is", without warranty of any kind.
Use at your own risk.
