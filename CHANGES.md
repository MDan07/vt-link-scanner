# VT Link Scanner 2.3.0

## Automatic download monitoring
- Added automatic detection of completed Chrome downloads.
- Added a desktop notification when a download finishes, with a direct "scan this download" workflow.
- The File Scanner can be opened directly for the detected download.
- After the user selects the matching local file, scanning starts automatically.
- Added a setting to turn completed-download monitoring on/off.
- Important: Chrome MV3 does not expose arbitrary Downloads-folder bytes to an extension, so a pure extension cannot silently hash/upload every downloaded file. True zero-click content scanning requires a Native Messaging companion/native helper.

# VT Link Scanner 2.2.0

# VT Link Scanner 2.1.1

## Bug fix / final audit
- Fixed and regression-checked API-key removal so deleting one key removes only the selected key.
- Re-audited the 2.1.0 scanner code for JavaScript syntax and manifest validity before release.

# VT Link Scanner 2.1.0

## New security features
- Deep Scan unknown URLs: the user can explicitly submit an unknown URL to VirusTotal, wait for analysis to complete, and then receive the resulting classification.
- Domain reputation lookup for unknown URLs. The URL itself is not submitted unless the user chooses Deep Scan.
- RDAP domain-age lookup for additional context on new domains.
- Local URL heuristics for deceptive `@`/userinfo URLs, IP-host URLs, punycode, very long URLs, many subdomains, higher-risk TLDs, heavy encoding, and unusually many query parameters.
- A separate heuristic risk score (0-100) with Low/Moderate/High/Critical levels. This is an extension heuristic, not a VirusTotal score.
- VirusTotal's known final redirect destination can be checked and included in the risk decision.

## Multiple API keys
- Multiple VirusTotal API keys are supported.
- Rate-limited/rejected keys are cooled down and the scanner rotates to another configured key.
- Existing 1.x single-key installations are migrated automatically.
- `.env` import/export remains available for moving keys between computers.

## Behavior
- Unknown links now offer **Scan it now** instead of only asking whether to open them.
- Deep Scan explicitly warns that submitting a URL may make it visible on VirusTotal.
- Heuristics never manufacture a malicious verdict by themselves; they can raise a clean/unknown result to a warning when enough risk signals exist.
- Existing caching, exceptions, same-site scanning, context-menu scanning, and direct post-scan navigation are preserved.

## Known limits
- RDAP registration dates depend on the registry and may be unavailable or privacy-redacted.
- VirusTotal's `last_final_url` is a known/reported destination, not a guarantee about a server's future redirect behavior.
- JavaScript-driven navigations such as `window.open()` and arbitrary `location=` assignments outside normal link clicks cannot all be intercepted by a content script.
- Browser-internal pages such as `chrome://` cannot be scanned by normal extension content scripts.

## 2.2.0 — File Scanner
- Added a dedicated VirusTotal File Scanner page.
- Added recent Chrome download discovery using the Downloads API.
- Files are hashed locally with SHA-256 first; known hashes are checked without re-uploading the file.
- Unknown files require an explicit user action before upload to VirusTotal.
- Added VirusTotal file-analysis polling and file scan history/cache.
- Added multi-key rotation and rate-limit handling for file API requests.
- Supports VirusTotal uploads up to 32 MB directly and uses VirusTotal's upload URL for larger supported files; local hashing is limited to 100 MB to avoid excessive memory use.
- Important Chrome limitation: the extension cannot silently read arbitrary downloaded-file bytes from the Downloads folder, so the user must select the file in the picker.
