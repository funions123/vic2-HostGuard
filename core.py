"""
Shared, OS-independent packet validation for the Victoria 2 filter.
"""

import time, collections, datetime

PORT_MIN = 1631          # valid Victoria 2 host ports span 1631-1640
PORT_MAX = 1640
HEADER   = 12            # bytes before the first record
OPCODE   = 6             # message type that carries the vulnerable name/lobby records
RATE_MAX = 200           # max packets/sec from a single source before we drop (flood guard)
WINDOW   = 1.0

DRY_RUN  = false          # True = log only, forward everything; False = actually drop
LOGFILE  = "vic2filter.log"

hits  = collections.defaultdict(list)   # src_ip -> recent timestamps
stats = collections.Counter()           # reason -> count

_logf = open(LOGFILE, "a", encoding="utf-8")

def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}"
    print(line)
    _logf.write(line + "\n")
    _logf.flush()

def u32(buf, off):
    """Read a big-endian uint32 at off."""
    return int.from_bytes(buf[off:off + 4], "big")

def too_fast(ip):
    now = time.time()
    q = hits[ip]
    q.append(now)
    while q and now - q[0] > WINDOW:
        q.pop(0)
    return len(q) > RATE_MAX

def classify(payload, src_addr):
    """Return a drop reason string, or None if the packet looks legitimate."""
    n = len(payload)
    if n > HEADER and payload[12] == OPCODE:
        if n < 20:
            return f"op6-runt({n})"            # too small to hold the length fields
        count = u32(payload, 0)
        record_size = u32(payload, 16)
        if count * record_size + HEADER != n:
            return f"op6-len(count={count},size={record_size},len={n})"
    if too_fast(src_addr):
        return "flood"
    return None

def verdict(payload, src_addr, src_port):
    """Classify a packet, log any hit, and return True to forward / False to drop."""
    reason = classify(payload, src_addr)
    if reason:
        stats[reason] += 1
        verb = "WOULD-DROP" if DRY_RUN else "DROP"
        log(f"{verb} {src_addr}:{src_port} {reason}")
        if not DRY_RUN:
            return False
    return True

def banner(layer):
    mode = "DRY_RUN" if DRY_RUN else "ENFORCING"
    log(f"Filtering UDP {PORT_MIN}-{PORT_MAX} [{layer}] - {mode}. Ctrl+C to stop.")

def close():
    log(f"Stopped. Totals: {dict(stats)}")
    _logf.close()
