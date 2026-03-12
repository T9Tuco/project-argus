# project argus

this is early. the tool works, but there's a lot more planned — better os fingerprinting, service version detection, traceroute, export formats, a tui dashboard, and more. treat this as v0.1 of something that's going to keep growing.

---

a python-based network scanner and monitor that runs directly as a script. no packaging, no install step — just clone, install two deps, and run. uses scapy for raw packet operations and rich for terminal output.

## dependencies

```
pip install scapy rich
```

- **scapy** — raw socket operations (arp, icmp, tcp syn). required for discovery, ping, and syn scanning
- **rich** — terminal tables, progress bars, colored output

most features need root/admin privileges for raw socket access. the tool checks this before doing anything and tells you exactly what to run.

## quickstart

```
git clone https://github.com/T9Tuco/project-argus.git
cd project-argus
pip install scapy rich
sudo python3 argus.py discover 192.168.1.0/24
```

---

## commands

### discover

arp/icmp sweep to find live hosts on a subnet.

```
sudo python3 argus.py discover <network>
```

```
sudo python3 argus.py discover 192.168.1.0/24
sudo python3 argus.py discover 10.0.0.0/8 --timeout 3 --retries 2
sudo python3 argus.py discover 192.168.0.0/24 --json
```

on local subnets (rfc1918) it sends arp who-has broadcasts — fast and reliable, doesn't depend on icmp being unfiltered. for anything else it falls back to icmp echo. if arp returns nothing, it also tries icmp as a fallback.

output shows: ip, mac address, avg rtt, os hint (from ttl), and status.

---

### scan

tcp port scan on a single host or ip. accepts ips, hostnames, and full urls — it strips the url and resolves dns automatically.

```
sudo python3 argus.py scan <target>
```

```
sudo python3 argus.py scan 192.168.1.1
sudo python3 argus.py scan 192.168.1.1 --deep
sudo python3 argus.py scan 192.168.1.1 -p 22,80,443,8080
sudo python3 argus.py scan github.com
sudo python3 argus.py scan https://example.com --json
```

**scan modes:**
- default: scans 26 common ports (see list below)
- `--deep`: scans all ports 1–1024
- `-p / --ports`: comma-separated list of specific ports

**how it works:**
- with root + scapy: tcp syn scan (half-open). sends a syn packet, classifies the response:
  - syn-ack → open, then sends rst to tear down the connection
  - rst → closed
  - no response → filtered
- without root: falls back to full tcp connect(). slower and noisier but doesn't need privileges

**default port list:**
`21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 27017`

output shows: port, state (open/filtered), service name, and rtt per port.

---

### ping

icmp echo with per-packet results and a stats summary at the end.

```
sudo python3 argus.py ping <target>
```

```
sudo python3 argus.py ping 8.8.8.8
sudo python3 argus.py ping 8.8.8.8 -c 20
sudo python3 argus.py ping google.com --timeout 1 --json
```

sends `count` icmp echo requests with a 500ms interval between them. collects per-packet rtt and builds stats. output includes:

- packets sent / received
- packet loss %
- min / avg / max rtt
- jitter (mean deviation between consecutive rtts)

---

### monitor

continuous network monitoring — runs discover + latency checks in a loop until ctrl+c.

```
sudo python3 argus.py monitor <network>
```

```
sudo python3 argus.py monitor 192.168.1.0/24
sudo python3 argus.py monitor 192.168.1.0/24 --interval 60
sudo python3 argus.py monitor 10.0.0.0/24 -i 10 --timeout 1
```

each sweep: discovers all live hosts, then sends 3 pings to each known host to update rtt and alive status. hosts that stop responding are marked as down but stay in the table so you can see the change.

---

## all flags

| flag | commands | default | description |
|---|---|---|---|
| `-t` / `--timeout` | all | `2.0` | per-probe timeout in seconds |
| `-r` / `--retries` | discover | `1` | retries per probe before giving up |
| `--deep` | scan | off | scan ports 1–1024 instead of common ports |
| `-p` / `--ports` | scan | — | comma-separated port list, e.g. `22,80,443` |
| `-c` / `--count` | ping | `10` | number of icmp echo requests to send |
| `-i` / `--interval` | monitor | `30.0` | seconds between sweeps |
| `--json` | discover, scan, ping | off | output results as json instead of tables |
| `--version` | — | — | print version and exit |

---

## privileges

| command | needs root | why |
|---|---|---|
| `discover` | yes | arp and icmp require raw sockets |
| `scan` (syn) | yes | raw tcp packet crafting |
| `scan` (connect) | no | fallback mode, uses normal tcp connect() |
| `ping` | yes | raw icmp sockets |
| `monitor` | yes | uses discover + ping internally |

if you run a command that needs root without it, argus exits immediately with a clear message and the correct `sudo` command to use.

---

## target input

all commands accept ips, hostnames, and urls. argus normalises the input before doing anything:

```
sudo python3 argus.py scan https://github.com     # strips to github.com, resolves to ip
sudo python3 argus.py ping google.com              # dns resolved automatically
sudo python3 argus.py scan 10.0.0.1               # used as-is
```

for `discover` and `monitor`, the target must be a cidr range. hostnames and urls are rejected with a clear error and an example.

---

## json output

every command except `monitor` supports `--json`. useful for piping into jq or other tools.

```bash
sudo python3 argus.py discover 192.168.1.0/24 --json | jq '.[] | select(.alive == true)'
sudo python3 argus.py scan 10.0.0.1 --deep --json | jq '.[] | select(.state == "open")'
sudo python3 argus.py ping 8.8.8.8 --json | jq '.avg_ms'
```

---

## os fingerprinting

argus makes a rough os guess based on the ip ttl value in icmp replies:

| ttl range | guess |
|---|---|
| 1–64 | linux / macos |
| 65–128 | windows |
| 129+ | network device |

this is intentionally rough. proper os fingerprinting (tcp window size, options, etc.) is on the roadmap.

---

## what's coming

this is an early version. planned additions, in no particular order:

- service version detection (banner grabbing)
- udp scanning
- traceroute with per-hop latency
- os fingerprinting using tcp stack analysis (not just ttl)
- exportable reports (json, csv, html)
- a full tui dashboard using textual
- scheduled monitoring with alerting
- ipv6 support
- config file support

---

## license

mit
