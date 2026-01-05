# OnionTalk

Secure talk sessions over the Tor Network, via port 8001 to a Tor Hidden Service.

---

## Fork Notice

This repository is a **fork** of `Ch1ff3rpunk/OnionTalk`.

The purpose of this fork is to explore **protocol hardening, security hygiene, and robustness improvements**.  
It is **not affiliated** with the original author.

Only the code contained in this repository is covered by its documentation and security policy.

---

## Changes in This Fork

This fork focuses on internal improvements while preserving the original protocol and user-facing behavior.

Notable changes include:

- Graceful shutdown using `context.Context` instead of hard `os.Exit` calls
- Explicit framed I/O for encrypted messages
- Improved error handling for network and I/O operations
- Directional key separation for client → server and server → client traffic
- In-memory protection of cryptographic secrets using `memguard`
- Clearer security scope and responsible disclosure policy (`SECURITY.md`)

No changes were made to:
- the wire format
- the cryptographic primitives
- the external usage model

The fork remains **backwards compatible** with existing OnionTalk clients.

---

## Security

Security considerations, threat scope, and vulnerability reporting guidelines are documented in  
[`SECURITY.md`](SECURITY.md).

---

## Disclaimer

This software is provided **as-is**, without warranty of any kind.  
It has not been formally audited and is intended for experimental and educational use.
