# VT Link Scanner 2.4.0

**Scan links before opening them with the power of VirusTotal.**

VT Link Scanner is a Chrome extension that checks HTTP and HTTPS URLs against [VirusTotal](https://www.virustotal.com/) to help identify potentially malicious websites, suspicious links, and unsafe destinations.

It combines VirusTotal threat intelligence with additional local URL-risk checks in a simple interface.

---

## Screenshots

<table>
  <tr>
    <td width="50%" align="center">
      <img src="screenshots/Screenshot%202026-11-02%20044004.png" width="100%" alt="VT Link Scanner - Theme 1">
    </td>
    <td width="50%" align="center">
      <img src="screenshots/Screenshot%202026-11-02%20044015.png" width="100%" alt="VT Link Scanner - Theme 2">
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <img src="screenshots/Screenshot%202026-11-02%20044035.png" width="100%" alt="VT Link Scanner - Theme 3">
    </td>
    <td width="50%" align="center">
      <img src="screenshots/Screenshot%202026-11-02%20044050.png" width="100%" alt="VT Link Scanner - Theme 4">
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <img src="screenshots/Screenshot%202026-11-02%20044106.png" width="100%" alt="VT Link Scanner - Theme 5">
    </td>
    <td width="50%" align="center">
      <img src="screenshots/Screenshot%202026-11-02%20044115.png" width="100%" alt="VT Link Scanner - Theme 6">
    </td>
  </tr>
  
  
</table>

URL Scan Results

Unknown Link — No completed VirusTotal analysis

<p align="center">
  <img src="screenshots/unknown%20link.png" width="100%" alt="Unknown link warning notification">
</p>

Safe Link — No engines flagged the URL

<p align="center">
  <img src="screenshots/scan%20result.png" width="100%" alt="Safe link scan result notification">
</p>
## Features

### URL Protection

- Checks HTTP and HTTPS links against VirusTotal.
- Multiple VirusTotal API keys with automatic rotation and cooldown.
- 24-hour caching for known reports and shorter caching for unknown results.
- Deep Scan for URLs that VirusTotal has never analyzed.
- Waits for VirusTotal analysis to finish before displaying Deep Scan results.
- Domain reputation lookup for unknown URLs.
- RDAP-based domain registration-age signals when available.
- Local URL-risk heuristics for common deceptive URL patterns.
- Separate extension heuristic risk score.
- Checks known final destinations and redirects when available.
- Optional same-site scanning.
- Right-click context menu: **Scan link with VirusTotal**.

### File Scanner

- Dedicated interface for scanning downloaded files.
- Displays recent Chrome downloads.
- Calculates SHA-256 locally before checking VirusTotal.
- Checks whether a file hash already has a VirusTotal report.
- Requests confirmation before uploading a file that VirusTotal has not seen.
- Supports local hashing of files up to 100 MB.
- Uses VirusTotal's larger-file upload URL where available.

### Appearance

- 28 selectable themes.
- 20 Glass / Liquid Glass themes.
- 8 additional design styles in the Beyond Glass collection.
- Theme selection is shared between the popup and File Scanner.
- Customizable visual appearance without changing the scanning engine.

### API Key Management

- Add multiple VirusTotal API keys.
- Automatic key rotation and cooldown handling.
- Import and export API keys using `.env` files.
- API keys are stored in extension storage and are not exposed to webpage content scripts.

---

## Installation

1. Download the latest ZIP from the [Releases page](https://github.com/MDan07/vt-link-scanner/releases).
2. Extract the ZIP file.
3. Open Chrome and navigate to:

   `chrome://extensions`

4. Enable **Developer mode**.
5. Click **Load unpacked**.
6. Select the extracted extension folder (the folder containing `manifest.json`).
7. Open VT Link Scanner and configure your VirusTotal API key.

---

## Getting a VirusTotal API Key

You need a VirusTotal account and an API key to use the scanning features.

If you have never used VirusTotal before, follow these steps:

### Step 1 — Create a VirusTotal account

Visit the official VirusTotal website:

[https://www.virustotal.com/](https://www.virustotal.com/)

1. Click **Sign up**.
2. Register using your email address.
3. Verify your email if requested.
4. Log in to your account.

### Step 2 — Open your API key page

Once logged in, visit the official API key page:

[**Get your VirusTotal API key**](https://www.virustotal.com/gui/my-apikey)

Your personal API key will be displayed on this page.

Copy the API key.

### Step 3 — Add your API key to VT Link Scanner

1. Open VT Link Scanner from the Chrome extensions menu.
2. Find the **VirusTotal API keys** section.
3. Paste your copied key into the API key input field.
4. Click **Add**.
5. Confirm that your key appears in the configured API keys list.

You can add multiple API keys if you have them.

**Important:** Keep your API key private. Never publish it in screenshots, GitHub commits, README files, or public messages.

### VirusTotal API limitations

VirusTotal applies usage limits to its API. The available limits depend on your account and API access level.

The public API is intended for non-commercial use and has strict request limits. Check VirusTotal's official documentation for the current restrictions:

[VirusTotal API Documentation](https://docs.virustotal.com/reference/overview)

---

## Deep Scan & Privacy

Deep Scan submits a URL to VirusTotal for analysis when no existing report is available.

**Do not submit URLs containing sensitive information**, including:

- Password-reset tokens.
- Private identifiers.
- Session tokens.
- Confidential links.
- Other URLs that should not be shared with third parties.

Submitting a URL to VirusTotal means sharing it with the service under its applicable policies.

---

## File Scanner & Download Monitoring

When **Automatic download monitoring** is enabled, the extension detects completed Chrome downloads and displays a desktop notification with a direct link to the File Scanner.

The extension then requires you to select the downloaded file through the file picker before it can access and scan the file's contents.

The scanner calculates the file's SHA-256 hash locally and checks VirusTotal for an existing report.

If no report exists, the extension asks for confirmation before uploading the file.

**Why is manual file selection required?**

Chrome's Manifest V3 Downloads API provides download metadata but does not give an extension unrestricted access to the downloaded file's contents.

Consequently, fully automatic scanning of arbitrary downloaded files without user interaction requires an additional native helper application using Native Messaging.

---

## Importing & Exporting API Keys

VT Link Scanner supports `.env` import and export to make it easier to migrate API keys between computers.

- On your old computer, use **Export .env**.
- Transfer the exported file securely.
- On your new computer, use **Import .env**.

The browser requires you to explicitly select the file. The extension cannot silently search your computer for `.env` files.

**Security warning:** The exported `.env` file contains sensitive API credentials. Keep it private and never upload it to GitHub.

---

## Security & Detection Disclaimer

VT Link Scanner is a security assistance tool, not a guarantee of protection.

- A clean VirusTotal result does not guarantee that a URL or file is safe.
- Detection results depend on the available VirusTotal engines and intelligence at the time of analysis.
- Local heuristic checks provide additional warning signals but are not definitive malware detections.
- The extension's heuristic risk score is separate from VirusTotal's detection results.
- Always exercise caution when opening unfamiliar links or files.

---

## Known Limitations

- VirusTotal API usage is subject to account-specific rate limits.
- Deep Scan submits previously unknown URLs to VirusTotal.
- Files must be explicitly selected through the file picker before their contents can be accessed.
- Browser extension popups cannot reliably sample the live webpage behind them. Glass transparency is therefore simulated within the extension interface.

---

## Changelog

See [CHANGES.md](https://github.com/MDan07/vt-link-scanner/blob/main/CHANGES.md) for version history and changes.

For release downloads, visit the [GitHub Releases page](https://github.com/MDan07/vt-link-scanner/releases).

---

## Disclaimer

VT Link Scanner is an independent project and is **not affiliated with, endorsed by, or officially associated with VirusTotal or Google Chrome**.

VirusTotal is a trademark of its respective owner.
