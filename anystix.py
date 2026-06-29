#!/usr/bin/env python3
"""
AnyStix — Harvest malicious public submissions from ANY.RUN by
submission country and emit a STIX 2.1 bundle (optionally push to OpenCTI).

Browserless: talks the Meteor DDP WebSocket that app.any.run uses (see
anyrun_ddp.py). No Chrome / Selenium / login required.

    armenia -> AM
      -> DDP method getAnalysisPublicMobileAdvancedTi  (country + dateRange)
      -> paginate via nextCursor, keep verdict.threat_level == 2 (malicious)
      -> STIX 2.1 bundle (incremental, deduped by task uuid)

The public feed exposes the URL/domain/filename + task uuid + tags, but NOT
file hashes, so file indicators match on file:name and every indicator carries
the ANY.RUN task link in external_references.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid as uuidlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

import pycountry

import anyrun_ddp

# Fixed identity id so repeated runs merge into one ANY.RUN source in OpenCTI.
IDENTITY_ID = "identity--a1111111-1111-4111-a111-111111111111"
IPV4 = __import__("re").compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


# ---------------------------------------------------------------------------
# Country + date helpers
# ---------------------------------------------------------------------------

def resolve_country(value: str) -> str:
    """Country name or code -> ISO 3166-1 alpha-2 UPPER (ANY.RUN shortName)."""
    value = value.strip()
    if len(value) == 2 and value.isalpha():
        c = pycountry.countries.get(alpha_2=value.upper())
        if c:
            return c.alpha_2.upper()
    if len(value) == 3 and value.isalpha():
        c = pycountry.countries.get(alpha_3=value.upper())
        if c:
            return c.alpha_2.upper()
    c = pycountry.countries.get(name=value)
    if not c:
        try:
            c = pycountry.countries.search_fuzzy(value)[0]
        except LookupError:
            c = None
    if not c:
        raise ValueError(f"could not resolve country: {value!r}")
    return c.alpha_2.upper()


def date_range_ms(days: int) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    return int(start.timestamp() * 1000), int(now.timestamp() * 1000)


# ---------------------------------------------------------------------------
# Item -> STIX indicator
# ---------------------------------------------------------------------------

def _iso(ms) -> str:
    if isinstance(ms, dict):           # EJSON {"$date": ...}
        ms = ms.get("$date")
    try:
        return datetime.fromtimestamp(int(ms) / 1000, timezone.utc)\
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def item_to_indicator(item: dict) -> dict | None:
    objects = item.get("public", {}).get("objects", {})
    run_type = objects.get("runType")
    names = objects.get("mainObject", {}).get("names", {})
    uuid = item.get("uuid")
    if not uuid:
        return None
    task_link = f"https://app.any.run/tasks/{uuid}"
    verdict = item.get("scores", {}).get("verdict", {})
    tags = [t for t in (item.get("tags") or []) if isinstance(t, str)]
    when = _iso(item.get("times", {}).get("taskStart"))

    extra_refs = []
    if run_type == "file":
        name = names.get("basename") or uuid
        esc_name = name.replace("'", "\\'")
        sha256 = item.get("_sha256")  # enriched upstream via getTaskByUUID
        if sha256:
            pattern = (f"[file:name = '{esc_name}' AND "
                       f"file:hashes.'SHA-256' = '{sha256}']")
            extra_refs.append({"source_name": "sha256", "external_id": sha256,
                               "description": "Main object SHA-256"})
        else:
            pattern = f"[file:name = '{esc_name}']"
        kind = "file"
    else:
        url = names.get("url") or names.get("basename") or ""
        target = url.strip()
        # Bare host (no scheme) -> domain-name / ipv4; otherwise url:value.
        if "://" not in target and "/" not in target and target:
            if IPV4.match(target):
                pattern, kind = f"[ipv4-addr:value = '{target}']", "ipv4-addr"
            else:
                pattern, kind = f"[domain-name:value = '{target.lower()}']", "domain-name"
            name = target
        else:
            host = urlparse(target).netloc or target
            esc = target.replace("'", "\\'")
            pattern, kind = f"[url:value = '{esc}']", "url"
            name = host or target

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuidlib.uuid4()}",
        "created": when,
        "modified": when,
        "name": name,
        "description": f"ANY.RUN public submission ({run_type}) — "
                       f"{verdict.get('text', 'malicious')}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": when,
        "labels": ["ANY RUN", "malicious", kind] + tags,
        "created_by_ref": IDENTITY_ID,
        "external_references": [
            {"source_name": "ANY.RUN", "url": task_link,
             "description": "ANY.RUN analysis task"},
            {"source_name": "anyrun-uuid", "external_id": uuid,
             "description": "ANY.RUN task uuid (dedup key)"},
        ] + extra_refs,
    }


IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": IDENTITY_ID,
    "created": "2025-04-15T12:00:00.000Z",
    "modified": "2025-04-15T12:00:00.000Z",
    "name": "ANY.RUN",
    "identity_class": "organization",
    "description": "Interactive malware analysis sandbox — public submissions feed",
    "contact_information": "support@any.run",
}


def load_existing(path: Path) -> tuple[list, set]:
    """Return (objects, seen_uuids) from an existing bundle for incremental runs."""
    if not path.exists():
        return [], set()
    try:
        bundle = json.loads(path.read_text())
    except (ValueError, OSError):
        return [], set()
    objs = bundle.get("objects", [])
    seen = set()
    for o in objs:
        if o.get("type") == "indicator":
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "anyrun-uuid":
                    seen.add(ref.get("external_id"))
    return objs, seen


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Harvest malicious ANY.RUN public submissions by country "
                    "-> STIX 2.1 (browserless DDP).")
    ap.add_argument("--country", required=True,
                    help="Country name or ISO code, e.g. 'armenia' or 'AM'.")
    ap.add_argument("--date-range", type=int, default=30,
                    help="Look-back window in days (default: 30).")
    ap.add_argument("--out", default=None,
                    help="Output bundle path (default: <CC>_anystix.json). "
                         "Existing bundle is updated incrementally.")
    ap.add_argument("--max-items", type=int, default=None,
                    help="Cap number of malicious items collected.")
    ap.add_argument("--include-suspicious", action="store_true",
                    help="Also include suspicious (threat_level 1); default malicious only.")
    ap.add_argument("--from-json", default=None,
                    help="Skip the network; build STIX from a saved feed JSON "
                         "(list of items, or a {items:[...]} object).")
    ap.add_argument("--no-hashes", action="store_true",
                    help="Skip per-task SHA-256 enrichment for file submissions "
                         "(faster; file indicators then match on file:name only).")
    ap.add_argument("--dump-items", default=None,
                    help="Also write the raw matched items to this JSON file.")
    ap.add_argument("--push-opencti", action="store_true",
                    help="Import the bundle into OpenCTI (needs OPENCTI_URL + "
                         "OPENCTI_TOKEN env vars; never hardcode the token).")
    args = ap.parse_args(argv)

    try:
        cc = resolve_country(args.country)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    start_ms, end_ms = date_range_ms(args.date_range)
    print(f"[*] Country: {args.country} -> {cc}", file=sys.stderr)
    print(f"[*] Window:  last {args.date_range} day(s)", file=sys.stderr)

    # Collect matching items.
    items: list[dict] = []
    if args.from_json:
        data = json.loads(Path(args.from_json).read_text())
        raw = data.get("items", data) if isinstance(data, dict) else data
        for it in raw:
            lvl = it.get("scores", {}).get("verdict", {}).get("threat_level")
            if lvl == 2 or (args.include_suspicious and lvl == 1):
                items.append(it)
    else:
        try:
            if args.include_suspicious:
                gen = anyrun_ddp.fetch_all(cc, start_ms, end_ms,
                                           malicious_only=False,
                                           max_items=args.max_items)
                items = [i for i in gen
                         if i.get("scores", {}).get("verdict", {})
                              .get("threat_level") in (1, 2)]
            else:
                items = list(anyrun_ddp.fetch_all(cc, start_ms, end_ms,
                                                  malicious_only=True,
                                                  max_items=args.max_items))
        except Exception as e:
            print(f"[!] DDP fetch failed: {e}", file=sys.stderr)
            return 1

    print(f"[*] Matched {len(items)} item(s)", file=sys.stderr)

    # Enrich file submissions with their main object's SHA-256 (per-task call).
    if not args.no_hashes and not args.from_json:
        files = [it for it in items
                 if it.get("public", {}).get("objects", {}).get("runType") == "file"]
        if files:
            print(f"[*] Fetching SHA-256 for {len(files)} file submission(s)...",
                  file=sys.stderr)
            got = 0
            for it in files:
                try:
                    sha = anyrun_ddp.get_task_sha256(it.get("uuid"))
                except Exception:
                    sha = None
                if sha:
                    it["_sha256"] = sha
                    got += 1
            print(f"[*] Resolved {got}/{len(files)} SHA-256 hash(es)", file=sys.stderr)

    if args.dump_items:
        Path(args.dump_items).write_text(json.dumps(items, indent=2))

    # Build / update the bundle.
    out_path = Path(args.out or f"{cc}_anystix.json")
    objects, seen = load_existing(out_path)
    if all(o.get("id") != IDENTITY_ID for o in objects):
        objects.append(IDENTITY)

    added = 0
    for it in items:
        if it.get("uuid") in seen:
            continue
        ind = item_to_indicator(it)
        if not ind:
            continue
        objects.append(ind)
        seen.add(it.get("uuid"))
        added += 1

    # STIX 2.1 bundles carry no spec_version (it lives on each object).
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuidlib.uuid4()}",
        "objects": objects,
    }
    out_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
    print(f"[+] {added} new indicator(s); bundle now {len(objects)} objects "
          f"-> {out_path}", file=sys.stderr)

    if args.push_opencti:
        return push_opencti(out_path)
    return 0


def push_opencti(bundle_path: Path) -> int:
    url = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        print("[!] Set OPENCTI_URL and OPENCTI_TOKEN env vars to push.",
              file=sys.stderr)
        return 2
    try:
        import urllib3
        from pycti import OpenCTIApiClient
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        client = OpenCTIApiClient(url, token, "error", ssl_verify=False)
        client.stix2.import_bundle_from_json(bundle_path.read_text())
        print(f"[+] Imported {bundle_path} into OpenCTI at {url}", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"[!] OpenCTI import failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
