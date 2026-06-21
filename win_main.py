"""
Windows front end: capture inbound UDP via WinDivert and apply core.verdict.
"""

import pydivert
import core

core.banner("Windows/WinDivert")

flt = f"udp.DstPort >= {core.PORT_MIN} and udp.DstPort <= {core.PORT_MAX} and inbound"
try:
    with pydivert.WinDivert(flt) as w:
        for packet in w:
            if core.verdict(packet.payload or b"", packet.src_addr, packet.src_port):
                w.send(packet)        # forward to the game untouched
            # else: not re-injected => dropped before the game sees it
except KeyboardInterrupt:
    pass
finally:
    core.close()
