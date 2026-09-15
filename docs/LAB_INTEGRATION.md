# Real lab / Vulhub validation

## Current state

The repository contains two offline fixtures (`scripts/local_lab.py` and
`scripts/poc_meta_lab.py`) plus unit-level target-lab tests. The existing
`test_httpbin_live.py` is a real network integration test, but it skips when
`httpbin.org` is unreachable. CI currently runs pytest and benchmark fixtures;
it does **not** start Docker or Vulhub, so those results must not be described
as end-to-end vulnerability findings.

`scripts/lab_profiles/vulhub.yaml` is an intentionally minimal operator profile.
It is a run contract, not a bundled target or a claim that a Vulhub scenario is
present in this checkout.

## Offline preparation and checks

These steps do not contact the network or start containers:

```powershell
python scripts\lab_preflight.py
pytest -m "not network" tests -q
pytest -m integration --collect-only
```

The preflight exits `2` when Docker is missing or its daemon is unavailable.
That is a truthful block, not a skipped or successful scan. A compose file and
target URL must be supplied by the authorized operator:

```powershell
python scripts\lab_preflight.py `
  --compose-file C:\path\to\vulhub\scenario\docker-compose.yml `
  --target-url http://127.0.0.1:8080
```

## Authorized live run

From the selected Vulhub scenario directory, inspect the compose project,
then explicitly start it:

```powershell
docker compose up -d
python ..\..\scan.py -t http://127.0.0.1:8080
docker compose down
```

Record the scenario revision, published ports, scan command, report artifact,
and expected findings separately. A container health check or a non-empty
report is not proof of detection; only scenario-specific assertions and
reproducible evidence establish an end-to-end result.

## Environment and CI boundaries

The scanner reads its normal `.env`/environment configuration (for example
`DANGEROUS_MODE`, model credentials, `REDIS_URL`, and optional
`OOB_INTERACTSH_SERVER`). Credentials are intentionally not part of the lab
profile. Current CI has no Docker/Vulhub job and should remain fixture-only
until an authorized runner, scenario pin, and evidence policy are provided.

## 2026-09-13 real-run record

- **Vulhub E2E blocked on this machine**: no WSL distro installed, Docker
  Desktop backend/daemon never becomes ready (`lab_preflight.py` exit 2,
  truthful block). No containers were started, no fixture substituted.
- **Vulhub revision pinned**: master `aeaf65793f147f29bd50841ef77f4e9cad07ecc7`
  (2026-09-13) in `%TEMP%\vulhub`; scenario list (weblogic/ssrf 7001;
  fastjson/1.2.45 8090→port conflict, must remap; log4j CVE-2021-44228 via
  solr:8.11.0 8983/5005; struts2 s2-045 2.3.30 8080; shiro 1.2.4 8080) ready to
  replay with `docker compose up -d`/`down` once Docker is available.
- **Local authorized E2E this day**: `_runtime_cache/reports/
  report_http___127_0_0_1_8090_20260913_111702.json` — 96 findings,
  total_engine_calls 686, elapsed 735s, 88 items with evidence +
  reproduction_steps + curl, `reproduced`=0, OOB collaborator assigned
  (`wf03km.dnslog.cn`) with 0 callbacks (miss_streak=6).
- **Out-of-band channel status**: public interactsh endpoints (oast.*) are
  unreachable from this network (TLS reset); only dnslog.cn (DNS) is usable.
  DNS-only exfil (SSRF host / Fastjson Inet4Address / Log4Shell `jndi:dns`)
  closed the loop with real callbacks. HTTP/LDAP exfil requires a self-hosted
  `OOB_INTERACTSH_SERVER=https://oob.example.com` (origin-only, trusted TLS in
  `.env`), which the code already supports.
