#!/usr/bin/env python3
"""
Browserless fetch of ANY.RUN public submissions by country, over the same
Meteor DDP WebSocket the app.any.run SPA uses. No Chrome/Selenium required.

Reverse-engineered call (captured from the live app):
    method : getAnalysisPublicMobileAdvancedTi
    params : [{ hash, runtype[], extension[], country, verdict[], threatName,
               fileHash, domain, ip, mitreId, sid, url,
               dateRange:[{$date:start_ms},{$date:end_ms}] }]
    reply  : { items:[...], totalHits, nextCursor:[ts, uuid] }
"""
from __future__ import annotations

import json
import random
import string
from websocket import create_connection

WS_HOST = "app.any.run"
DDP_METHOD = "getAnalysisPublicMobileAdvancedTi"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/135.0.0.0 Safari/537.36")


def _sockjs_url() -> str:
    server = f"{random.randint(0, 999):03d}"
    session = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"wss://{WS_HOST}/sockjs/{server}/{session}/websocket"


def _send(ws, obj: dict) -> None:
    # sockjs client->server framing: a JSON array of message strings.
    ws.send(json.dumps([json.dumps(obj)]))


def _messages(frame: str):
    """Yield decoded DDP messages from one sockjs frame.

    'o' = open, 'h' = heartbeat, 'a[...]' = array of JSON message strings,
    'c[...]' = close.
    """
    if not frame or frame[0] not in "ac":
        return
    for raw in json.loads(frame[1:]):
        try:
            yield json.loads(raw)
        except (ValueError, TypeError):
            continue


def call_method(method: str, params: list, *, timeout: int = 30):
    """Open a DDP session, invoke one method, return its result (or raise)."""
    ws = create_connection(
        _sockjs_url(), timeout=timeout,
        header=[f"User-Agent: {UA}"], origin=f"https://{WS_HOST}")
    try:
        ws.recv()  # 'o'
        _send(ws, {"msg": "connect", "version": "1", "support": ["1"]})
        sent = False
        while True:
            frame = ws.recv()
            if frame == "h":
                continue
            for msg in _messages(frame):
                kind = msg.get("msg")
                if kind == "connected" and not sent:
                    _send(ws, {"msg": "method", "method": method,
                               "params": params, "id": "1"})
                    sent = True
                elif kind == "failed":
                    raise RuntimeError(f"DDP negotiation failed: {msg}")
                elif kind == "result" and msg.get("id") == "1":
                    if "error" in msg:
                        raise RuntimeError(f"method error: {msg['error']}")
                    return msg.get("result")
            if frame and frame[0] == "c":
                raise RuntimeError(f"connection closed: {frame}")
    finally:
        try:
            ws.close()
        except Exception:
            pass


def get_task_sha256(task_uuid: str, *, timeout: int = 30) -> str | None:
    """Fetch a task by uuid and return its main object's SHA-256 (or None)."""
    res = call_method("getTaskByUUID", [task_uuid], timeout=timeout)
    if not isinstance(res, dict):
        return None
    sha = (res.get("public", {}).get("objects", {})
              .get("mainObject", {}).get("hashes", {}).get("sha256"))
    return sha or None


def fetch_page(country_code: str, start_ms: int, end_ms: int, *,
               cursor=None, method: str = DDP_METHOD, timeout: int = 30) -> dict:
    """Open a DDP session, call the feed method once, return the result dict
    {items, totalHits, nextCursor}. Pass cursor (the previous reply's
    nextCursor) to page forward."""
    ws = create_connection(
        _sockjs_url(),
        timeout=timeout,
        header=[f"User-Agent: {UA}"],
        origin=f"https://{WS_HOST}",
        suppress_origin=False,
    )
    try:
        ws.recv()  # 'o' open frame
        _send(ws, {"msg": "connect", "version": "1", "support": ["1"]})

        flt = {
            "hash": "", "runtype": [], "extension": [], "country": country_code,
            "verdict": [], "threatName": "", "fileHash": "", "domain": "",
            "ip": "", "mitreId": "", "sid": "", "url": "",
            "dateRange": [{"$date": start_ms}, {"$date": end_ms}],
        }
        if cursor is not None:
            flt["cursor"] = cursor   # server paginates on this key
        params = [flt]
        call_id = "1"
        connected = False
        sent = False
        while True:
            frame = ws.recv()
            if frame == "h":  # heartbeat
                continue
            for msg in _messages(frame):
                kind = msg.get("msg")
                if kind == "connected" and not sent:
                    connected = True
                    _send(ws, {"msg": "method", "method": method,
                               "params": params, "id": call_id})
                    sent = True
                elif kind == "failed":
                    raise RuntimeError(f"DDP version negotiation failed: {msg}")
                elif kind == "result" and msg.get("id") == call_id:
                    if "error" in msg:
                        raise RuntimeError(f"method error: {msg['error']}")
                    return msg.get("result") or {}
            if not connected and frame and frame[0] == "c":
                raise RuntimeError(f"connection closed before connect: {frame}")
    finally:
        try:
            ws.close()
        except Exception:
            pass


def fetch_all(country_code: str, start_ms: int, end_ms: int, *,
              malicious_only: bool = True, max_items: int | None = None,
              max_pages: int = 200, method: str = DDP_METHOD, timeout: int = 30):
    """Paginate the feed via nextCursor, yielding matching item dicts.

    malicious_only keeps only verdict.threat_level == 2.
    Stops when a page is empty, nextCursor stops advancing, max_pages is hit,
    or max_items collected.
    """
    cursor = None
    seen_cursors = set()
    collected = 0
    for _ in range(max_pages):
        res = fetch_page(country_code, start_ms, end_ms,
                         cursor=cursor, method=method, timeout=timeout)
        items = res.get("items") or []
        if not items:
            break
        for it in items:
            if malicious_only:
                lvl = it.get("scores", {}).get("verdict", {}).get("threat_level")
                if lvl != 2:
                    continue
            yield it
            collected += 1
            if max_items and collected >= max_items:
                return
        cursor = res.get("nextCursor")
        key = tuple(cursor) if isinstance(cursor, list) else cursor
        if not cursor or key in seen_cursors:
            break
        seen_cursors.add(key)


if __name__ == "__main__":
    import sys
    cc = sys.argv[1] if len(sys.argv) > 1 else "AM"
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1767124800000
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1782763199999
    res = fetch_page(cc, start, end)
    items = res.get("items", [])
    mal = [i for i in items
           if (i.get("scores", {}).get("verdict", {}).get("threat_level") == 2)]
    print(f"country={cc} totalHits={res.get('totalHits')} "
          f"page_items={len(items)} malicious_in_page={len(mal)}")
    for i in mal[:10]:
        o = i.get("public", {}).get("objects", {})
        names = o.get("mainObject", {}).get("names", {})
        print(f"  [{o.get('runType')}] {names.get('url') or names.get('basename')}"
              f"  tags={i.get('tags')}  uuid={i.get('uuid')}")
