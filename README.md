# VT Link Scanner 2.4.0

A Chrome MV3 extension that checks HTTP(S) links against VirusTotal before opening them.

## What's new in 2.4.0
- 28 selectable appearance themes: 20 existing Glass / Liquid Glass themes plus 8 non-glass design-language themes.
- New non-glass themes are grouped under **Beyond Glass** and marked with **✦✦ NEW**.
- Improved contrast and readability across text, controls, inputs, buttons, and status surfaces.
- Theme selection is shared by the popup and File Scanner.

See [CHANGES.md](CHANGES.md) for the full changelog.


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


## Appearance themes (visual-only update)

The interface includes 12 selectable dark glass finishes: Midnight, Arctic, Aurora, Emerald, Sapphire, Amethyst, Rose Quartz, Graphite, Solar Flare, Deep Ocean, Cyberpunk, and Carbon. The selected appearance is shared between the extension popup and File Scanner using extension-origin local storage.

This visual update adds `theme.js` and updates the popup/File Scanner HTML and CSS. The scanner engine, API-key cycling, VirusTotal requests, permissions, settings behavior, download detection, and file-scanning logic are unchanged.

**Glass transparency limitation:** Chromium extension action popups are rendered as separate browser surfaces. CSS backdrop blur can style and blur the popup's own layered surfaces, but cannot reliably sample the live webpage behind the popup. The File Scanner tab can show layered glass over its own ambient background; the popup uses a simulated glass finish.


## Glass Collection — Contrast Edition

The appearance system includes 20 dark glass finishes. The original 12 themes are retained, with 8 additional themes marked **✦ NEW** in the theme palette:

- Obsidian
- Cobalt
- Lunar Silver
- Crimson Noir
- Jade Empire
- Ultraviolet
- Glacier
- Copper Luxe

The palette uses a custom high-contrast selector with visible swatches, readable labels, selected-state styling, and a small NEW marker on added themes. Theme selection is saved locally and shared between the extension popup and File Scanner page.

The visual refinement increases secondary-text contrast and improves focus and hover visibility. Browser extension popups cannot reliably sample the webpage behind the popup; blur and translucency are therefore simulated within the extension surface.


### Appearance themes
The appearance picker keeps the original 20 glass finishes and adds 12 non-glass design languages: Swiss Clarity, Paper & Ink, Terminal CRT, Neo-Brutalist, Bauhaus, Material 3, Clay Studio, Y2K Chrome, Dark Academia, E-Ink Paper, Frutiger Aero, and Editorial Noir. New styles are marked with a double star (✦✦ NEW). The new options deliberately change surface treatment, typography mood, control shape, and contrast—not just the accent color.


## Beyond Glass — refined design languages
- Preserved all 20 original Glass Collection themes and all 8 added contrast-edition themes.
- Retained 8 non-glass design languages: Swiss Clarity, Paper & Ink, Terminal CRT, Material 3, Dark Academia, E-Ink Paper, Frutiger Aero, and Editorial Noir.
- Removed Neo-Brutalist, Bauhaus, Clay Studio, and Y2K Chrome from the picker because their visual treatment was too loud/inconsistent for the scanner interface.
- Corrected helper/secondary text, warning banners, form controls, cards, and buttons with theme-matched contrast tokens.
- Isolated the theme picker styling so the selected theme cannot recolor its own option buttons.
- Kept the double-star (✦✦ NEW) marker on every retained new design language.
