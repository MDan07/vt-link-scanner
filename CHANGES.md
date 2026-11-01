# VT Link Scanner — Changelog

## [2.4.0] — 2026-11-02

### Added
- Added a theme collection with 20 original Glass / Liquid Glass themes and 8 additional non-glass design-language themes.
- Added a dedicated **Beyond Glass** theme section in the Appearance selector.
- Added double-star (`✦✦ NEW`) markers to identify the newly introduced non-glass themes.
- Added persistent theme selection shared by the extension popup and File Scanner.

### Improved
- Improved theme contrast for primary text, secondary text, buttons, inputs, placeholders, and warning/status surfaces.
- Isolated the Beyond Glass theme picker styling so selected theme button rules do not unintentionally restyle the theme tiles.
- Refined the retained new-theme collection for clearer, more consistent presentation.

### Theme collection
- Existing themes retained: 20.
- New non-glass themes retained: 8.
- Four visually heavy additions from the first Beyond Glass draft were removed after review.
- Existing link scanning, VirusTotal API-key rotation, file scanning, download monitoring, and scanner behavior are unchanged in this release.

### Notes and limitations
- Theme contrast was checked at the design-token level; browser rendering can vary by browser, operating system, and display settings.
- Chrome Manifest V3 does not provide extensions with unrestricted access to arbitrary downloaded-file bytes. Download monitoring still requires the user to select the downloaded file for content scanning.
- A clean VirusTotal result is not a guarantee that a URL or file is safe.

---

## [2.3.0]
- First packaged public release. See the GitHub release notes and repository history for the 2.3.0 feature set.
