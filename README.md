# vic2 HostGuard

An inline UDP packet filter for Victoria 2 hosts. It intercepts traffic to the game ports, drops malformed packets that crash the game, and forwards legitimate traffic untouched.

## What it protects against

Victoria 2's netcode crashes on a malformed lobby packet as follows: an attacker sends a join request packet like a normal client, then sends a forged player-name broadcast whose declared body length is smaller than the actual size of the datagram body. The UDP parser buffer overflows and the host crashes.

The filter validates the length self-consistency of the game's `opcode-06` messages. Every legitimate `opcode-06` packet satisfies:

```
count(payload[0:4]) * record_size(payload[16:4]) + 12 == len(payload)
```

Anything that breaks this equation is dropped. The exploit itself relies on sending a wrongly-sized packet. Testing has shown that an attacker manually sending correctly formed packets has no effect on the host or the game.

## Layout

| file | purpose |
|------|---------|
| `core.py` | shared, OS-independent validation logic |
| `win_main.py` | Windows front end (WinDivert) |
| `linux_main.py` | Linux front end (NFQUEUE) |
| `.github/workflows/build.yml` | Nuitka-compiles a standalone binary per platform |

## Getting a binary

The **Actions** workflow builds both platforms. Download from the run's **Artifacts**:

- `vic2hostguard-windows` -> `vic2hostguard-win.exe`
- `vic2hostguard-linux` -> `vic2hostguard-linux`

The binaries are standalone; no Python install is needed on the host. (On Linux
the system library `libnetfilter-queue1` must be present: `sudo apt-get install
libnetfilter-queue1`.)

## Running it

The filter starts in **`DRY_RUN` mode** (see `core.py`). It logs what it *would* drop to `vic2hostguard.log` but forwards everything. This is functionally a 'silent' mode the host can use if he desires.

### Windows

Run from an **Administrator** console (WinDivert loads a kernel driver):

```
vic2hostguard-win.exe
```

### Linux

Run as **root**, with an NFQUEUE rule directing the game ports into the queue:

```
sudo iptables -A INPUT -p udp --dport 1631:1640 -j NFQUEUE --queue-num 0
sudo ./vic2hostguard-linux
```

Tear the rule down when finished (same command with `-D` instead of `-A`):

```
sudo iptables -D INPUT -p udp --dport 1631:1640 -j NFQUEUE --queue-num 0
```

IPv4 only; add an equivalent `ip6tables` rule if you host over IPv6.

## Configuration

Settings live at the top of `core.py`:

| setting | meaning |
|---------|---------|
| `PORT_MIN`, `PORT_MAX` | game port range to inspect (default 1631-1640) |
| `DRY_RUN` | `True` = log only; `False` = drop |
| `RATE_MAX` | per-source packets/sec before the flood guard trips |
| `LOGFILE` | where dropped/flagged packets are recorded |

## Building locally

Nuitka cannot cross-compile, so you will need to build each platform on the OS in question.

```
# Windows
pip install nuitka pydivert
python -m nuitka --onefile --include-package-data=pydivert --output-filename=vic2hostguard-win.exe win_main.py

# Linux
sudo apt-get install -y libnetfilter-queue-dev patchelf
pip install nuitka NetfilterQueue
python -m nuitka --onefile --output-filename=vic2hostguard-linux linux_main.py
```
