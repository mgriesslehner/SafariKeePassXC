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

### Security model

- **Host app <-> KeePassXC:** encrypted with the KeePassXC-Browser protocol (NaCl `crypto_box`).
- **Safari extension ↔ host app:** a local Unix socket inside the extension's sandbox
  container. Every connection must first present a random token from the Keychain; the
  messages on this link are *not* encrypted a second time. They never leave your Mac.
- Nothing is sent over the network.
- **Clipboard:** generated passwords and TOTP codes you copy from the popup are placed on
  the system clipboard and stay there until something else is copied. Clipboard managers
  or Universal Clipboard (Handoff) may keep or sync them.

## Requirements

- macOS 26.5 (Tahoe) or later, with the Safari version that ships with it
- [KeePassXC](https://keepassxc.org) installed, with the browser integration enabled in
  **Settings → Browser Integration**
- Xcode 26 or later to build the app

## Download

- [SafariKeePassXC Official Website](https://www.griesslehner.at/safarikeepassxc.html) 

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
