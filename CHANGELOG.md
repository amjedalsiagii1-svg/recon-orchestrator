# Changelog

## [SF Desktop 0.4.0] — 2026-11-20

### Changed
- Replaced the XML-first inventory page with a one-click local device analysis workflow.
- XML imports remain an optional advanced capability and are no longer needed for normal use.

### Added
- Read-only local interface, private address, default route, DNS, and listening-socket snapshot.
- Automatic session creation when starting the first local analysis.
- Local snapshot provenance in SQLite and in the HTML report.
- Clear warning that local listening sockets do not prove Internet reachability.

### Safety
- No active network discovery, packet transmission, remote target checks, or root privileges in quick analysis.


## [SF Desktop 0.3.0] — 2026-11-20

### Added
- Arabic desktop workspace for sessions, evidence, recommendations, and local command guidance.
- Offline import of existing Nmap XML files with strict local-scope filtering.
- Asset and service inventory stored in SQLite with source-file SHA-256 deduplication.
- Explicit authorization confirmation recorded with every inventory import.
- Asset, service, import provenance, and authorization details included in the standalone HTML session report.
- XML size, host-count, and service-count limits; DTD and ENTITY declarations rejected.

### Quality
- 26 foundation tests pass on Python 3.11 and 3.12.
- 7 headless Qt integration tests pass.
- Existing main branch remains unchanged.


## [0.6.0] — 2026-10-25

### Added
- LAN discovery via mDNS, SSDP, NetBIOS (no root required)
- Progress indicators for long phases
- Platform + capabilities detection
- Bilingual UI (Arabic + English)
- Plugin system (add CVE via YAML)
- 22 CVEs included
- CIDR support in Scope Guard
- Session resume (`--resume <ID>`)
- Sessions list (`l` command)

### Changed
- CVEs load from YAML plugins (22 KB → 2 KB code)
- Phase 3 fully translated to Arabic
- Duration labels bilingual

### Fixed
- Nuclei detection verifies execution
- Interface detection fallbacks
- Path brute-force false positives eliminated (34 → 7)
- Input markup leak fixed

### Tests
- 164 passing (was 89 in v0.5.0)

## [0.5.0] — 2026-10-23
- Bilingual CLI + plugin loader foundation

## [0.4.0] — 2026-10-21
- Interactive Rich CLI, dir brute, default creds

## [0.3.0] — 2026-10-18
- HTML Arabic report + Downloads

## [0.2.0] — 2026-10-15
- 7 phases + Scope Guard + SQLite + 89 tests

## [0.1.0] — 2026-10-10
- Initial scaffold
