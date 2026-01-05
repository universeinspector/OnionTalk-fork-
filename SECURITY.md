# Security Policy

## Supported Versions

This project is currently in active development.


Only the latest commit on the `main` branch receives security updates.

## Project Origin

This repository is a **fork** of an upstream project.

Security fixes and changes in this repository apply **only to this fork** and may not be present in the original upstream project.

Vulnerabilities that also affect the upstream project should be reported to the upstream maintainers as well.

This fork introduces additional changes, including:
- refactored message framing
- improved error handling
- graceful shutdown logic
- directional key separation
- memory hardening using memguard

Only the code present in this repository is covered by this security policy.


## Security Model (Overview)

This project provides **end-to-end encrypted communication over Tor** with the following properties:

- Transport anonymity via **Tor (SOCKS5)**
- Ephemeral key exchange using **X25519 (ECDH)**
- Directional key separation (client→server / server→client)
- Authenticated encryption using **AES-GCM**
- Explicit message framing
- Graceful shutdown with context cancellation
- In-memory protection of sensitive material using **memguard**

### Threats addressed
- Passive network surveillance
- IP address disclosure
- Message tampering
- Memory scraping after process exit
- Accidental plaintext transmission

### Non-goals / Out of scope
- Identity authentication (no user verification)
- Protection against compromised endpoints
- Forward secrecy across multiple sessions
- Traffic analysis resistance beyond Tor guarantees

---

## Reporting a Vulnerability

Please **do not open public issues** for security vulnerabilities.

Instead, report vulnerabilities **privately**:

📧 **Contact:**  
GitHub private security advisory if available

### What to include
- Clear description of the issue
- Steps to reproduce (if applicable)
- Potential impact assessment
- Affected code paths or functions


---

## Responsible Disclosure

I follow a **responsible disclosure policy**:
- Vulnerabilities will be investigated 
- Fixes will be released before public disclosure whenever possible
- Credit will be given to reporters if desired

---

## Cryptographic Notes

- All cryptographic primitives are sourced from Go's standard library
- No custom cryptography is implemented
- Keys and shared secrets are zeroed from memory after use
- Randomness is sourced exclusively from `crypto/rand`

---

## Disclaimer

This software is provided **as-is**, without warranty of any kind.  
It is intended for educational and experimental use and has **not been formally audited**.

Use at your own risk.
   