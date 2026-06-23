# Security Policy

This repository must not contain live credentials, private keys, operator
bundles, exported VPN kits, database dumps, or generated incident evidence.

## Secret Handling

- Use environment variables, Vault, or host-local files for secrets.
- Keep examples as placeholders only.
- Never print or commit live tokens, passwords, private keys, `.env` files, or
  generated credentials.
- Rotate any credential that is accidentally exposed before continuing work.

## Reporting Security Issues

For this private repository, report issues directly through the project owner or
the internal operator channel. Include:

- affected file or service
- exploit path or operational impact
- minimum reproduction steps
- suggested fix or mitigation, if known
