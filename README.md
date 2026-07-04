# POC-Hunter

CLI tool to discover CVEs for a product/version query and then hunt public POCs for each CVE.

## What it does

- CVE discovery from **NVD**, **CIRCL**, **OSV**, **Vulners**, and **GitHub Advisories**
- All CVE sources queried concurrently, results deduplicated
- POC discovery from **poc-in-github** with a configurable worker pool (max 8)
- Direct POC mode with `--poc` / `-poc`
- Version variant matching (example: `2.2.0` can match `v2.2.x`)
- Selectable CVE sources via `--sources` flag
- Proper table formatting with word-wrapped DETAIL column
- Vulners source uses `/api/v4/audit/software` (CPE-based, partial match, extended catalog)

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
- add optional source hints:
  - `--vendor <vendor>`
  - `--ecosystem <ecosystem>`
  - `--sources <list>` — restrict CVE sources (comma-separated: `nvd,circl,osv,vulners,github`)

```bash
go run ./cmd/pochunter --search <KEYWORDS>
go run ./cmd/pochunter --app "<APP-NAME>" --version <VERSION>
go run ./cmd/pochunter --search Krayin CRM 2.20 --vendor Webkul --ecosystem php
go run ./cmd/pochunter --app django --version 3.2 --ecosystem PyPI --timeout 20s
go run ./cmd/pochunter --search django 4.2 --sources nvd,vulners
```

Optional API-backed CVE sources:

```bash
export VULNERS_API_KEY="<your-vulners-key>"
export GITHUB_TOKEN="<your-github-token>"
```

These are automatically included when their env var is set, and can be filtered with `--sources`.

### 2) Direct POC mode

Skip CVE discovery and directly search POCs by CVE ID.

```bash
go run ./cmd/pochunter -poc CVE-2026-38526
go run ./cmd/pochunter -poc CVE 2026 38526
```

## Available CVE sources

| Flag     | Source            | Auth              | Notes |
|----------|-------------------|-------------------|-------|
| `nvd`    | NVD API 2.0       | None              | Keyword search with version-variant fallback filtering. `resultsPerPage=200`. |
| `circl`  | CIRCL CVE search  | None              | Queries `cve.circl.lu/api/search/{vendor}/{product}`. Falls back to `vendor=product` if vendor is empty. |
| `osv`    | OSV.dev           | None              | Package-ecosystem based. **Requires `--ecosystem`**. POSTs version+package to `api.osv.dev/v1/query`. Resolves aliases to CVEs. |
| `vulners`| Vulners v4 audit  | `VULNERS_API_KEY` | Uses `POST /api/v4/audit/software` with structured CPE objects (`"match": "partial"`, `"catalog": "extended"`). |
| `github` | GitHub Advisories | `GITHUB_TOKEN`    | **Requires `--ecosystem`**. Queries `api.github.com/advisories` with ecosystem+package filter. |

## Flags

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| `--search`       | Keyword search mode                              |
| `--poc` / `-poc` | Direct POC mode (CVE ID input)                   |
| `--app`          | Application/product name                         |
| `--version`      | Application version                              |
| `--vendor`       | Vendor name (search hint)                        |
| `--ecosystem`    | Package ecosystem (`npm`, `pypi`, `go`, `maven`, `rubygems`, etc.) |
| `--sources`      | Comma-separated CVE sources to query             |
| `--timeout`      | Request timeout (default 30s)                    |

## CVE discovery 

1. All selected CVE sources are queried **concurrently** via goroutines.
2. Results are **deduplicated** by CVE + source + detail.
3. Unique CVE IDs are collected and sorted.
4. For each unique CVE, all POC sources are queried (worker pool, **max 8** concurrent).
5. POC findings are flattened and sorted by CVE → owner → URL.

## POC sources

| Source          | Description                                      |
|-----------------|--------------------------------------------------|
| `poc-in-github` | Queries `poc-in-github.motikan2010.net/api/v1/?cve_id=` |

## TODO:

- [ ] Add more POC providers
- [ ] Add output formats (JSON/CSV).
- [ ] Add caching and retry/backoff.
- [ ] Add unit tests for version canonicalization and source adapters.
