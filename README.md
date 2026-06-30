# AnyStix

Harvest **malicious public submissions from ANY.RUN by submission country** and
emit a **STIX 2.1** bundle (optionally push straight into OpenCTI).

![AnyStix-harvested IoCs imported into OpenCTI — the ANY.RUN organization with a full STIX bundle (111 indicators)](docs/opencti-import.jpg)

<sub>AnyStix output imported into **OpenCTI**: the country's malicious submissions land as a STIX bundle under the ANY.RUN organization, ready for correlation and proactive defense.</sub>

> ### "Sell me this pen."
>
> In *The Wolf of Wall Street*, the trick was never the pen — it was first
> creating the **need**: *"write your name on this napkin."* No pen, no name.
> Suddenly the pen is essential.
>
> Threat intelligence is the same. You can't block, detect, or hunt what you
> can't **see** — and right now, malware is being detonated **from and against
> your country** in ANY.RUN's public feed, while your defenses wait on next
> quarter's vendor report. The gap between *"a threat is hitting my region"* and
> *"my firewall knows about it"* is where breaches happen.
>
> **AnyStix is the pen.** It puts a live, country-specific stream of real threats
> in your hand — as ready-to-action IoCs — so you defend *before* the incident,
> not after.

## Why

[ANY.RUN](https://app.any.run/submissions) runs one of the largest **free,
public interactive malware sandboxes** on the internet — thousands of fresh
samples and URLs are detonated there every day, and every public analysis is
openly available. That firehose is a goldmine of **fresh, real-world threat
intelligence**, but it isn't organised around *your* threat model.

**AnyStix turns that public feed into a country-focused intel source.** Point it
at a country (e.g. `armenia`) and it pulls the malware and malicious URLs that
were **actually submitted from / targeting your region**, keeps only the
confirmed-malicious verdicts, enriches executables with their **SHA-256**, and
packages everything as standards-compliant **STIX 2.1**.

The result is an intelligence source you own and can act on for **proactive
defense**: feed the extracted **IoCs** (file hashes, URLs, domains, IPs) into
your detection and blocking stack — SIEM, firewall/proxy denylists, EDR, DNS
sinkholes — *before* those samples reach your users. Run it on a schedule
(systemd timer included) and the bundle grows incrementally as new threats
appear in your region.

Because the output is plain **STIX 2.1**, those IoCs import cleanly into
open-source threat-intelligence platforms — most notably **[OpenCTI](https://www.opencti.io/)**
(built-in `--push-opencti`), as well as MISP, Microsoft Sentinel, ThreatConnect,
and anything else that speaks STIX/TAXII — so the intelligence slots straight
into your existing workflow.

```
armenia ─▶ AM
        ─▶ Meteor DDP method getAnalysisPublicMobileAdvancedTi (country + dateRange)
        ─▶ paginate via nextCursor, keep verdict.threat_level == 2 (malicious)
        ─▶ STIX 2.1 bundle (incremental, deduped by task uuid)  ─▶ OpenCTI
```

## Browserless — how it works

`app.any.run` is a **Meteor.js** app; its public-submissions data is **not**
HTML or REST — it streams over a **Meteor DDP WebSocket** (`/sockjs/.../websocket`).
This tool speaks that protocol directly:

1. Open `wss://app.any.run/sockjs/<id>/<sess>/websocket`, send DDP `connect`.
2. Call method **`getAnalysisPublicMobileAdvancedTi`** with the filter object
   `{country:"AM", dateRange:[{$date:start},{$date:end}], ...}`.
3. Read the `result` → `{items[], totalHits, nextCursor}`; page forward by
   passing `cursor: <nextCursor>` until exhausted.
4. Keep items with `scores.verdict.threat_level == 2` and map to STIX.

No Chrome, no Selenium, no login, no Turnstile — and the output is clean JSON
instead of scraped HTML. (Country filtering needs no account; it is a plain
field on the public feed.)

`anyrun_ddp.py` is the self-contained DDP client; `anystix.py` is the CLI.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Malicious AM submissions from the last 30 days -> AM_anystix.json
python anystix.py --country armenia --date-range 30

# Cap volume / widen verdicts / choose output
python anystix.py --country armenia --max-items 200 --out armenia.json
python anystix.py --country DE --include-suspicious

# Push to OpenCTI (token from env — never hardcode it)
export OPENCTI_URL=https://127.0.0.1
export OPENCTI_TOKEN=********-****-****-****-************
python anystix.py --country armenia --push-opencti

# Offline: build STIX from previously captured items (see --dump-items)
python anystix.py --country armenia --from-json AM_items.json

# Quick smoke test of the raw fetcher
python anyrun_ddp.py AM
```

### ⚠️ OpenCTI: enable automatic import (read this before scheduling `--push`)

`--push-opencti` hands the raw bundle to OpenCTI's `uploadImport` mutation and
lets the platform's own **ImportFileStix** connector + worker parse it — so the
push never breaks on a client/server version mismatch (no `pycti` dependency).

**By default, OpenCTI does not import the file automatically.** If the
`connector-import-file-stix` connector runs with `CONNECTOR_VALIDATE_BEFORE_IMPORT=true`,
every upload creates an **analyst workbench that a human must open and validate**
before any IoC becomes searchable. Validating one workbench does **not** carry
over to the next — so a scheduled run (e.g. hourly) produces a **new
unvalidated workbench every single run**, forever. This is almost certainly not
what you want for an automated feed.

To make imports fully hands-off, set this on the connector and restart it:

```yaml
# docker-compose.yml
connector-import-file-stix:
  environment:
    - CONNECTOR_VALIDATE_BEFORE_IMPORT=false
```

```bash
docker compose up -d connector-import-file-stix
```

| `CONNECTOR_VALIDATE_BEFORE_IMPORT` | Workbench created? | Manual validation? |
|---|---|---|
| `true` (default)  | every upload | **required every time** |
| `false`           | never        | never — imports straight into the knowledge base |

Watch an upload's progress under **Data → Import**; once imported, the IoCs
appear under **Observations → Indicators** (author **ANY.RUN**).

| Option | Description |
|--------|-------------|
| `--country` | Country name or ISO code (`armenia`, `AM`, `arm`). **Required.** |
| `--date-range` | Look-back window in days (default `30`). |
| `--out` | Output bundle path (default `<CC>_anystix.json`); updated incrementally. |
| `--max-items` | Cap malicious items collected. |
| `--include-suspicious` | Also include `threat_level == 1`. |
| `--no-hashes` | Skip per-task SHA-256 enrichment (file indicators then match on `file:name` only). |
| `--dump-items` | Also write the raw matched feed items to a JSON file. |
| `--from-json` | Build STIX from saved items instead of the network. |
| `--push-opencti` | Upload the bundle to OpenCTI for its worker to ingest (needs `OPENCTI_URL`/`OPENCTI_TOKEN`). Uses only the standard library — no `pycti`. |

## Run on a schedule (systemd, Ubuntu)

`install-service.sh` installs a hardened **systemd service + timer** for **one
country**. Each run writes to a persistent bundle under
`/var/lib/anystix/<country>_anystix.json`; because the tool dedups by task
UUID, every run appends **only new** malicious entries.

```bash
# install + schedule (hourly by default), copies app to /opt/anystix
sudo ./install-service.sh install --country armenia --interval 1h --date-range 30

# with OpenCTI push: fill /etc/anystix.env then add --push
sudo ./install-service.sh install --country armenia --push

sudo ./install-service.sh run-now             # trigger one harvest immediately
sudo ./install-service.sh status              # timer state + bundle
sudo ./install-service.sh logs                # recent journal output
sudo ./install-service.sh uninstall [--purge] # remove (--purge also drops data)
```

Notes: runs unprivileged via `DynamicUser` + `StateDirectory`; `--interval`
accepts systemd spans (`30min`, `1h`, `6h`). To track a different country,
re-run `install` with a new `--country` (it overwrites the unit).

## Output

![A terminal run of AnyStix: matching items, SHA-256 enrichment, and the resulting STIX indicator patterns](docs/anystix-demo.png)

STIX 2.1 `bundle` with:

- one `identity` ("ANY.RUN", fixed id so repeated runs merge into one source);
- one `indicator` per submission:
  - file → `[file:name = '...']`, url → `[url:value = '...']`, bare host →
    `[domain-name:value=...]` / `[ipv4-addr:value=...]`;
  - `labels: ["ANY RUN", "malicious", <kind>, *tags]`;
  - `external_references`: the ANY.RUN task link **and** an `anyrun-uuid`
    entry used as the incremental **dedup key**.

## Notes & limitations

- The public feed list has no hashes, so for each **file** submission the tool
  makes a second DDP call — `getTaskByUUID(uuid)` — and reads the main object's
  **SHA-256** from `public.objects.mainObject.hashes.sha256` (md5/sha1 ignored).
  File indicators then match on `file:name AND file:hashes.'SHA-256'`, and the
  SHA-256 is added as a `source_name:"sha256"` external reference. Use
  `--no-hashes` to skip this (one extra request per file submission).
- `getAnalysisPublicMobileAdvancedTi` is the "mobile" variant of the feed method
  (captured from the live app); there is a desktop twin that returns the same
  data. Override via `anyrun_ddp.DDP_METHOD` if ANY.RUN renames it.
- Respect ANY.RUN's Terms of Service and rate limits.
