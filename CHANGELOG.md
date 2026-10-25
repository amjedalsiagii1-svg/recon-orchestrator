# Changelog

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
