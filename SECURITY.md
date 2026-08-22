# Security policy

## Threat model

The GPT client may make mistakes or be compromised. Server-side capabilities are
authoritative: OpenAPI is convenience and discovery, not a security boundary.
Guessed URLs or operations are rejected by the server. The read-only lockdown is a
separate server-side boundary for all mutations.

## Prepare/apply

Mutations use a short TTL, are single-use, and are bound to the authenticated
Home Assistant user and session plus the exact normalized mutation and digest.
Apply uses idempotency. If an outcome is uncertain, use
`system.prepare.status` or `system.apply.status`; never retry blindly.

## Public artifact

The HACS artifact is target-only. Source, Git, bootstrap, release-mutation
code, and their capabilities are removed during the public build. The build
fails closed if a private marker or source-only implementation leaks.

## OAuth

Home Assistant's native OAuth/IndieAuth authorization endpoint owns the
authorization and `state` flow. Callback URIs are allowlisted. One Bridge
passes through a valid PKCE verifier, but does not validate the challenge or
persist OAuth session grants or token values. Home Assistant owns session
lifecycle and revocation. Rotate the OAuth client credential through Options.

## Compromise and recovery

If OAuth access may be compromised, revoke the Home Assistant session, rotate
the One Bridge OAuth client credential, and review the audit log.
