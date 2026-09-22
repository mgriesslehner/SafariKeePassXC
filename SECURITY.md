# Security Policy

SafariKeePassXC bridges Safari to your local KeePassXC database, so security issues here can expose
saved logins and passwords. If you find a vulnerability, please report it privately rather than opening
a public issue.

## Reporting a Vulnerability

Email **markus@griesslehner.at** with a description of the issue and, if possible, steps to reproduce.
Please do not disclose the issue publicly until a fix has been released.

## Scope

Security-relevant areas include:

- The `BridgeServer` Unix socket relay between the sandboxed Safari extension and the host app, and its
  token-based authentication (`BridgeToken.swift`)
- The KeePassXC-Browser protocol implementation and its NaCl/libsodium encryption
  (`KeePassXCClient.swift`, `KeePassXCCrypto.swift`)
- Keychain usage for storing the bridge token
- The Safari extension's native messaging and content-script handling of credentials

General bugs that don't have security impact (UI glitches, autofill not matching a site, etc.) should
be reported as normal GitHub issues instead.
