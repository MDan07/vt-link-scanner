# VT Link Scanner 2.4.0 — Expanded Theme Collection

This release expands the appearance system while preserving the existing scanner functionality.

## What's new
- **28 themes total:** all 20 existing Glass / Liquid Glass themes are retained.
- **8 new non-glass themes** are added in a separate **Beyond Glass** section.
- New themes are marked with **✦✦ NEW** so they are easy to identify.
- Improved readability across primary/secondary text, buttons, input fields, placeholders, and warning/status surfaces.
- Theme picker styling is isolated so theme-specific button styles do not break the theme selector.
- Theme selection remains consistent between the extension popup and File Scanner.

## Existing functionality
URL scanning, VirusTotal integration, API-key rotation, Deep Scan, file scanning, download monitoring, privacy controls, and other scanner workflows are carried forward unchanged.

## Installation
1. Download and extract the source ZIP.
2. Open `chrome://extensions` (or `brave://extensions`).
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extracted `VT-Link-Scanner-2.4.0` folder.

## Important notes
- VirusTotal clean results do not guarantee safety.
- Completed-download monitoring detects downloads, but the user must still select the local file before its contents can be scanned; this is a Chrome MV3 filesystem-access limitation.
- Chrome may restrict installation of CRX files distributed outside the Chrome Web Store. Load unpacked is the fallback.
