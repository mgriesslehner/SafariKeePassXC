# Contributing

Thanks for your interest in contributing to SafariKeePassXC!

## Reporting security issues

Please don't open a public issue for security vulnerabilities — see [SECURITY.md](SECURITY.md) instead.

## Development setup

1. Open `SafariKeePassXC.xcodeproj` in Xcode.
2. Select your own Development Team in the signing settings for both the `SafariKeePassXC` and
   `SafariKeePassXC Extension` targets. This is required for local code signing and only affects your
   local build.
3. Build and run the `SafariKeePassXC` scheme, then enable the extension in Safari under
   **Settings → Extensions**.

## Before opening a pull request

- **Don't commit signing changes.** If your diff includes a changed `DEVELOPMENT_TEAM` value or other
  signing-related settings in `project.pbxproj`, please revert that part before opening the PR — those
  values are specific to your local Apple Developer account.
- Run the existing tests in `SafariKeePassXCTests` and make sure they pass.
- Keep pull requests focused on a single change; unrelated formatting or refactoring changes make
  review harder.
- For anything beyond a small fix, consider opening an issue first to discuss the approach.
