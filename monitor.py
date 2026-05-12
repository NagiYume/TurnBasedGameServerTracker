#!/usr/bin/env python3
"""
HSR Server Dispatch Monitor

Continuously monitors Honkai: Star Rail beta server dispatch endpoints
to detect server status changes (online / closed / non-existent).

Version format: A.B.5C  (B ∈ [0,8], C ∈ [0,5])
Scan starts from: 4.0.50

Status classification:
  ACTIVE  - server is online, response contains gateway list (field 4)
  CLOSED  - version expired, response code 4
  INVALID - version does not exist, response code 3
"""

import requests
import base64
import time
import sys
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────

BASE_URL = "https://globaldp-beta-cn01.bhsr.com/query_dispatch"
POLL_INTERVAL = 5
REQUEST_TIMEOUT = 10
SCAN_DELAY = 0.3
MAX_INITIAL_SCAN = 100
CONSECUTIVE_NA_LIMIT = 5
RESCAN_EVERY = 60

FIXED_PARAMS = {
    "language_type": "1",
    "platform_type": "3",
    "channel_id": "1",
    "sub_channel_id": "1",
    "is_new_format": "1",
}


# ── Protobuf Wire Format Decoder (no .proto schema needed) ────────────────

def _read_varint(buf, pos):
    val = 0
    sh = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << sh
        if not (b & 0x80):
            return val, pos
        sh += 7
    raise ValueError("truncated varint")


def _validate_message(buf):
    """Return bytes consumed if buf looks like valid protobuf, else 0."""
    if len(buf) < 2:
        return 0
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = _read_varint(buf, pos)
        except ValueError:
            return 0
        fn, wt = tag >> 3, tag & 7
        if fn < 1 or wt not in (0, 1, 2, 5):
            return 0
        try:
            if wt == 0:
                _, pos = _read_varint(buf, pos)
            elif wt == 1:
                if pos + 8 > len(buf):
                    return 0
                pos += 8
            elif wt == 2:
                ln, pos = _read_varint(buf, pos)
                if pos + ln > len(buf):
                    return 0
                pos += ln
            elif wt == 5:
                if pos + 4 > len(buf):
                    return 0
                pos += 4
        except (ValueError, IndexError):
            return 0
    return pos


def decode_protobuf(buf):
    """Decode protobuf wire-format bytes into {field_number: value, ...}.

    Repeated fields become lists.  Length-delimited fields that look like
    nested messages are recursively decoded; others are decoded as UTF-8
    strings (falling back to raw bytes).
    """
    if not buf:
        return {}
    out = {}
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = _read_varint(buf, pos)
        except ValueError:
            break
        fn, wt = tag >> 3, tag & 7
        if fn < 1 or wt not in (0, 1, 2, 5):
            break
        try:
            if wt == 0:
                val, pos = _read_varint(buf, pos)
            elif wt == 1:
                val = buf[pos : pos + 8]
                pos += 8
            elif wt == 2:
                ln, pos = _read_varint(buf, pos)
                raw = buf[pos : pos + ln]
                pos += ln
                if _validate_message(raw) == len(raw):
                    val = decode_protobuf(raw)
                else:
                    try:
                        val = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        val = raw
            elif wt == 5:
                val = buf[pos : pos + 4]
                pos += 4
            else:
                break
        except (ValueError, IndexError):
            break
        if fn in out:
            prev = out[fn]
            out[fn] = [prev, val] if not isinstance(prev, list) else prev + [val]
        else:
            out[fn] = val
    return out


# ── Response Classification ───────────────────────────────────────────────

ACTIVE = "active"
CLOSED = "closed"
INVALID = "invalid"
ERROR = "error"


def classify(raw):
    """Classify a raw protobuf response.

    Returns (status, detail_dict) where status is one of
    ACTIVE / CLOSED / INVALID / ERROR.
    """
    d = decode_protobuf(raw)
    if not d:
        return ERROR, {"msg": "empty or unparseable response"}

    # ACTIVE: contains field 4 (repeated gateway info messages)
    if 4 in d:
        svrs = d[4]
        if not isinstance(svrs, list):
            svrs = [svrs]
        if all(isinstance(s, dict) for s in svrs):
            return ACTIVE, {"servers": svrs}

    # CLOSED / INVALID / ERROR: field 1 (code varint) + field 2 (message string)
    if 1 in d and 2 in d:
        code = d[1]
        msg = d[2]
        if isinstance(msg, bytes):
            try:
                msg = msg.decode("utf-8")
            except UnicodeDecodeError:
                msg = repr(msg)
        if code == 4:
            return CLOSED, {"code": code, "msg": msg}
        if code == 3:
            return INVALID, {"code": code, "msg": msg}
        return ERROR, {"code": code, "msg": msg}

    return ERROR, {"fields": {str(k): repr(v) for k, v in d.items()}}


# ── Version Helpers ───────────────────────────────────────────────────────

def ver_str(a, b, c):
    """(4, 2, 3) → '4.2.53'"""
    return f"{a}.{b}.5{c}"


def ver_next(a, b, c):
    """Next version, wrapping B and C."""
    c += 1
    if c > 5:
        c = 0
        b += 1
        if b > 8:
            b = 0
            a += 1
    return a, b, c


def ver_prev(a, b, c):
    """Previous version, wrapping B and C.  Returns None if a < 1."""
    c -= 1
    if c < 0:
        c = 5
        b -= 1
        if b < 0:
            b = 8
            a -= 1
            if a < 1:
                return None
    return a, b, c


# ── HTTP Fetch ────────────────────────────────────────────────────────────

def fetch(ver):
    """Fetch dispatch data for *ver* (e.g. '4.2.53').

    Returns decoded raw protobuf bytes, or None on network error.
    """
    params = {
        **FIXED_PARAMS,
        "version": f"CNBETAWin{ver}",
        "t": str(int(time.time())),
    }
    try:
        r = requests.get(BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return base64.b64decode(r.text.strip())
    except Exception:
        return None


# ── Display Helpers ───────────────────────────────────────────────────────

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _svr_names(svrs):
    parts = []
    for s in svrs:
        n = s.get(5, "?")
        if isinstance(n, bytes):
            n = n.decode("utf-8", errors="replace")
        parts.append(str(n))
    return ", ".join(parts)


def show(ver, st, det, prefix=""):
    if st == ACTIVE:
        print(f"{prefix}[{ts()}] {ver}  ONLINE  ({_svr_names(det['servers'])})")
    elif st == CLOSED:
        print(f"{prefix}[{ts()}] {ver}  CLOSED  {det['msg']}")
    elif st == INVALID:
        print(f"{prefix}[{ts()}] {ver}  N/A")
    else:
        print(f"{prefix}[{ts()}] {ver}  ERROR   {det}")


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  HSR Server Dispatch Monitor")
    print(f"  Endpoint : {BASE_URL}")
    print(f"  Versions : A.B.5C  (B=0~8, C=0~5)")
    print(f"  Start    : 4.0.50")
    print("=" * 70)

    # state: (a,b,c) → (status, detail, raw_bytes)
    states = {}
    active_set = set()
    monitor_set = set()

    # ── Phase 1: Initial scan ─────────────────────────────────────────────
    print(f"\n[{ts()}] Phase 1 – scanning for active servers …\n")

    a, b, c = 4, 0, 0
    na_streak = 0

    for _ in range(MAX_INITIAL_SCAN):
        v = ver_str(a, b, c)
        raw = fetch(v)
        if raw:
            st, det = classify(raw)
            states[(a, b, c)] = (st, det, raw)
            show(v, st, det, "  ")
            if st == ACTIVE:
                active_set.add((a, b, c))
                na_streak = 0
            elif st == INVALID:
                na_streak += 1
                if na_streak >= CONSECUTIVE_NA_LIMIT and active_set:
                    print(f"\n  Stopped after {na_streak} consecutive N/A responses.")
                    break
            else:
                na_streak = 0
        else:
            print(f"  [{ts()}] {v}  FETCH FAILED")
            na_streak += 1
        a, b, c = ver_next(a, b, c)
        time.sleep(SCAN_DELAY)

    # Build monitor set: only the last active server + its neighbours
    last_active = max(active_set) if active_set else None

    def rebuild_monitor():
        monitor_set.clear()
        if last_active:
            va, vb, vc = last_active
            monitor_set.add((va, vb, vc))
            pv = ver_prev(va, vb, vc)
            if pv:
                monitor_set.add(pv)
            nv = ver_next(va, vb, vc)
            monitor_set.add(nv)

    rebuild_monitor()

    if last_active:
        print(f"\nLast active: {ver_str(*last_active)}")
        print(f"Monitoring : {' '.join(ver_str(*v) for v in sorted(monitor_set))}")
    else:
        print(f"\n[{ts()}] No active servers found – will keep scanning.")

    cursor = (a, b, c)  # resume position for periodic re-scan

    # ── Phase 2: Continuous polling ───────────────────────────────────────
    print("\n" + "-" * 70)
    print(f"[{ts()}] Phase 2 – polling every {POLL_INTERVAL}s  (Ctrl+C to quit)")
    print("-" * 70 + "\n")

    last_scan = time.time()

    try:
        while True:
            # --- poll all monitored versions ---
            for va, vb, vc in sorted(monitor_set):
                v = ver_str(va, vb, vc)
                raw = fetch(v)
                if raw is None:
                    continue

                st, det = classify(raw)
                key = (va, vb, vc)
                old = states.get(key)

                if old:
                    if raw != old[2]:  # response bytes changed
                        print()
                        print("!" * 70)
                        print(f"  CHANGE DETECTED @ {ts()}  |  version {v}")
                        print(f"    was : ", end="")
                        show(v, old[0], old[1])
                        print(f"    now : ", end="")
                        show(v, st, det)
                        print("!" * 70)
                        print()
                        states[key] = (st, det, raw)

                        # update active / monitor sets
                        if st == ACTIVE:
                            if last_active is None or key > last_active:
                                last_active = key
                            active_set.add(key)
                            rebuild_monitor()
                        else:
                            active_set.discard(key)
                else:
                    states[key] = (st, det, raw)

                time.sleep(SCAN_DELAY)

            # --- periodic re-scan for new versions ---
            if time.time() - last_scan >= RESCAN_EVERY:
                last_scan = time.time()
                sa, sb, sc = cursor
                print(f"\n[{ts()}] Re-scanning from {ver_str(sa, sb, sc)} …")
                for _ in range(12):
                    v = ver_str(sa, sb, sc)
                    key = (sa, sb, sc)
                    if key not in states:
                        raw = fetch(v)
                        if raw:
                            st, det = classify(raw)
                            states[key] = (st, det, raw)
                            show(v, st, det, "  ")
                            if st == ACTIVE:
                                active_set.add(key)
                                if last_active is None or key > last_active:
                                    last_active = key
                                rebuild_monitor()
                    sa, sb, sc = ver_next(sa, sb, sc)
                    time.sleep(SCAN_DELAY)
                cursor = (sa, sb, sc)
                if monitor_set:
                    print(
                        f"  Monitoring: {' '.join(ver_str(*v) for v in sorted(monitor_set))}"
                    )
                print()

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n[{ts()}] Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
