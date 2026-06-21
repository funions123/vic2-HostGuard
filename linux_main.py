"""
Linux front end: receive queued packets via NFQUEUE and apply core.verdict.
"""

import socket
from netfilterqueue import NetfilterQueue
import core

QUEUE_NUM = 0

def handle(pkt):
    raw = pkt.get_payload()                  # full IPv4 packet
    ihl = (raw[0] & 0x0F) * 4                 # IPv4 header length in bytes
    src_addr = socket.inet_ntoa(raw[12:16])
    udp = raw[ihl:]
    src_port = int.from_bytes(udp[0:2], "big")
    payload = udp[8:]                         # skip the 8-byte UDP header
    if core.verdict(payload, src_addr, src_port):
        pkt.accept()
    else:
        pkt.drop()

core.banner(f"Linux/NFQUEUE q{QUEUE_NUM}")

nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, handle)
try:
    nfqueue.run()
except KeyboardInterrupt:
    pass
finally:
    nfqueue.unbind()
    core.close()
