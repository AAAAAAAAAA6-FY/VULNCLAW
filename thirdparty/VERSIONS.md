# Third-party tool versions

> Snapshot of the bundled tools under `thirdparty/` versus the latest official upstream releases.
> Last verified against the official GitHub Releases API: 2026-08-30.

| Tool | Upstream | Bundled version in this repo | Latest official release | Status |
| --- | --- | --- | --- | --- |
| nuclei | projectdiscovery/nuclei | `v3.11.1` (verified via `nuclei.exe -version`) | `v3.11.1` (2026-08-08) | Up to date |
| ffuf | ffuf/ffuf | `v2.2.1` (verified via `ffuf.exe -V`) | `v2.2.1` (2026-07-13) | Up to date |
| subfinder | projectdiscovery/subfinder | `v2.16.0` (verified via `subfinder.exe -version`) | `v2.16.0` (2026-08-22) | Up to date |
| interactsh-client | projectdiscovery/interactsh | 无版本号（二进制不暴露 version 字符串） | `v1.3.1` (2026-03-10) | Manual check required |

## Notes

- All bundled binaries were probed locally on 2026-08-30: `nuclei.exe -version`, `ffuf.exe -V`, `subfinder.exe -version`, `interactsh-client.exe -version`.
- `nuclei` and `ffuf` are already at the latest official stable release (confirmed via the GitHub Releases API on 2026-08-30).
- `subfinder` upgraded to `v2.16.0` (the latest official release). This release adds the `scanmalware` passive source, honors `-max-results` in paginated sources, and fixes strict domain matching plus the crtsh `statement_timeout` issue.
- `interactsh-client` prints its ASCII banner but does not expose a version tag; compare the binary against the upstream `interactsh` v1.3.1 release manually.
- Earlier notes in this file marked nuclei/ffuf as outdated; those were based on incomplete data and have been corrected.
