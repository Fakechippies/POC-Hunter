# POC-Hunter

CLI tool to discover CVEs for a product/version query and then hunt public POCs for each CVE.

## What it does

- CVE discovery from NVD
- POC discovery from poc-in-github
- Direct POC mode with `--poc` / `-poc`
- Version variant matching (example: `2.2.0` can match `v2.2.x`)

## Install

```bash
go install github.com/Fakechippies/pochunter/cmd/pochunter@latest
```

Then run:

```bash
pochunter --search <APP-NAME> <VERSION>
```

## Modes

### 1) Keyword mode (default)

Use one of these:
- `--search <product words...> <version>`
- `--app <product> --version <version>`

```bash
go run ./cmd/pochunter --search <KEYWORDS>
go run ./cmd/pochunter --app "<APP-NAME>" --version <VERSION>
```

Example:

```bash
go run ./cmd/pochunter --app Krayin CRM 2.20
```

Current working:
1. Query NVD for CVEs using product/version.
2. If strict query is empty, fallback to product-only.
3. Filter fallback results using generated version variants.
4. Query POC source(s) for each CVE found.

### 2) Direct POC mode

Skip CVE discovery and directly search POCs by CVE ID.

```bash
go run ./cmd/pochunter -poc CVE-2026-38526
go run ./cmd/pochunter -poc CVE 2026 38526
```

## Currently working on / TODO:

- [ ] Add more CVE providers (GitHub Advisory, CVE.org).
- [ ] Add more POC providers (ExploitDB, Packet Storm, custom GitHub search).
- [ ] Add output formats (JSON/CSV).
- [ ] Add caching and retry/backoff.
- [ ] Add unit tests for version canonicalization and source adapters.
