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
- Keychain usage for storing the bridge token and the KeePassXC association (data protection keychain)
- The Safari extension's native messaging and content-script handling of credentials

## Known Design Decisions

- **The host app is not sandboxed.** It has to reach KeePassXC's Unix socket, which a sandboxed app cannot
  do. The Safari extension itself stays sandboxed and only talks to the host app through the token-
  authenticated bridge socket. A compromise of the host app therefore has the full privileges of the user.
- **Credentials are plaintext in process memory and on the local sockets.** Autofill needs the clear-text
  password in the content script. The sockets are local, owned by the user, and the bridge requires the
  token; the KeePassXC leg uses KeePassXC-Browser's encryption.
- **Autofill runs in the top frame only** (`all_frames` is disabled), so embedded cross-origin frames
  can't receive credentials.
- **Socket timeouts** bound every connect, send and receive, so a hung peer can't block the app forever.

General bugs that don't have security impact (UI glitches, autofill not matching a site, etc.) should
be reported as normal GitHub issues instead.
