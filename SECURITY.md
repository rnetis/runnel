# Security Policy

## Supported versions

Runnel is experimental software. There are currently no stable releases with a security support guarantee. The maintainers will make a best effort to investigate reports affecting the default branch and actively maintained release branches.

## Reporting a vulnerability

**Do not open a public GitHub issue for an undisclosed vulnerability.**

Use GitHub's private vulnerability reporting feature for this repository (the **Report a vulnerability** button on the Security tab), if enabled. If private reporting is unavailable, contact the repository owner through a private channel listed on their GitHub profile and request a secure disclosure route.

Please include:

- A concise description of the issue and its potential impact.
- Affected commit, version, feature flags, and operating system.
- A minimal reproduction or proof of concept, where safe.
- Any relevant logs with private keys, PSKs, tokens, and personal data removed.

Do not send production credentials or live customer traffic captures.

## Scope

Security-sensitive areas include packet parsing, Noise handshake handling, key derivation and updates, nonce and packet-number management, replay protection, session authorization, address migration, transport framing, resource limits, and TUN/routing behavior.

## Disclosure

Please allow maintainers reasonable time to investigate and prepare a fix before public disclosure. Coordinated disclosure details and timelines should be agreed with the reporter.

## Security status

Runnel has not yet undergone an independent protocol or cryptographic audit. It must not be relied upon for sensitive or production traffic until the project explicitly announces a supported stable release and publishes its security review status.
