# VT Link Scanner 2.3.0

A Chrome MV3 extension that checks HTTP(S) links against VirusTotal before opening them.

## Main features

- Multiple VirusTotal API keys with automatic rotation/cooldown.
- 24-hour cache for known reports and shorter cache for unknown results.
- Explicit **Deep Scan** for URLs that VirusTotal has never analyzed.
- Waits for VirusTotal analysis to complete before showing the Deep Scan result.
- Domain reputation lookup for unknown URLs.
- RDAP-based domain registration-age signal when available.
- Local URL-risk heuristics for common deceptive URL patterns.
- Separate extension heuristic risk score (not a VirusTotal score).
- VirusTotal known final-destination/redirect checks.
- Same-site scanning toggle.
- Context-menu "Scan link with VirusTotal".
- `.env` import/export for API-key backup and migration.
- API keys remain in extension storage and are not exposed to page content scripts.

## Deep Scan privacy
Deep Scan submits the URL to VirusTotal. Do not use it on URLs containing secrets such as password-reset tokens, private identifiers, or session tokens unless you are comfortable submitting that URL to VirusTotal.

## Install
1. Extract the ZIP.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the extracted extension folder.
6. Add one or more VirusTotal API keys in the popup.

## `.env` migration
Use **Export .env** on the old computer and **Import .env** on the new computer. The browser requires the user to explicitly choose the file; an extension cannot silently search the computer for `.env` files.

The file is plain text and must be kept private.

## Security model
The extension does not claim that a VirusTotal clean result guarantees safety. A clean result means that the available VirusTotal signals did not flag the resource at the time of analysis. Heuristic signals are advisory and can increase a warning level but do not independently label a URL as malicious.

Not affiliated with VirusTotal.

## Automatic download monitoring

Completed Chrome downloads are detected automatically when the **Automatic download monitoring** setting is enabled. You receive a desktop notification with a direct link to the File Scanner.

Because Chrome's MV3 Downloads API exposes download metadata but not arbitrary local file bytes, the extension still requires one file-picker selection for the actual bytes. Once the user selects the detected file, the scan starts automatically.

A completely zero-click scan of arbitrary downloaded files is not possible with an extension alone. That requires a Native Messaging companion/native helper with local filesystem access.

## File Scanner

VT Link Scanner now includes a dedicated **File Scanner**. It can show recent Chrome downloads and lets you select a downloaded file for scanning.

The scanner first calculates the file's SHA-256 locally and checks VirusTotal's existing file report. If the hash is unknown, it asks before uploading the file. This avoids unnecessary uploads and makes the privacy boundary explicit.

Chrome extensions cannot silently read arbitrary local downloaded-file bytes, so a completed download cannot be uploaded automatically just from the Downloads API. The user must select the file. Files up to 100 MB can be locally hashed; VirusTotal upload handling supports the normal direct endpoint and its larger-file upload URL where available.
