# SafariKeePassXC

A Safari Web Extension that connects Safari to [KeePassXC](https://keepassxc.org) using the same
[KeePassXC-Browser protocol](https://github.com/keepassxreboot/keepassxc-browser) implemented by the
official browser extensions for Chrome and Firefox. It lets you autofill logins, save new entries, and
generate passwords directly from Safari on macOS, backed by your local KeePassXC database.

## How it works

KeePassXC exposes a local Unix domain socket that browser extensions connect to and encrypt messages
over using NaCl/libsodium public-key crypto (the same handshake used by the official KeePassXC-Browser
extension).

Safari Web Extensions, however, run in a sandboxed app extension process and cannot reach that socket
directly. SafariKeePassXC works around this with a small relay:

```
Safari Extension (sandboxed)  <--Unix socket-->  Host App (BridgeServer)  <--Unix socket-->  KeePassXC
```

- The **host app** (`SafariKeePassXC`) is not sandboxed and talks to KeePassXC's socket directly via
  `KeePassXCClient` / `KeePassXCCrypto`, using [Sodium](https://github.com/jedisct1/swift-sodium) for
  the crypto.
- It also runs a `BridgeServer` that listens on a Unix socket placed *inside the extension's own
  sandbox container*, so the sandboxed extension is allowed to connect to it.
- Every connection to that bridge socket must present a token from the Keychain before any request is
  served, so other local processes that find the socket path can't query KeePassXC through it.
- The extension's background script (`background.js`) talks to the bridge via native messaging
  (`HostBridgeConnection.swift` / `SafariWebExtensionHandler.swift`), and `content.js` / `popup.js`
  handle the in-page autofill UI.

## Requirements

- macOS with Safari
- [KeePassXC](https://keepassxc.org) installed, with the browser integration enabled in
  **Settings → Browser Integration**
- Xcode to build the app

## Building

1. Open `SafariKeePassXC.xcodeproj` in Xcode.
2. Select your own Development Team in the project's signing settings for both the `SafariKeePassXC`
   and `SafariKeePassXC Extension` targets (required for local code signing).
3. Build and run the `SafariKeePassXC` scheme.
4. Enable the extension in Safari under **Settings → Extensions**.

## Tests

Unit tests covering the crypto/bridge layer live in `SafariKeePassXCTests`. Run them from Xcode or via
`xcodebuild test`.

## License

SafariKeePassXC is licensed under the [GNU General Public License v3.0](LICENSE).

It depends on [Sodium](https://github.com/jedisct1/swift-sodium) (ISC License), a Swift wrapper around
[libsodium](https://libsodium.org), fetched as a Swift Package Manager dependency.
