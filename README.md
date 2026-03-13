# argus

a python-based network scanner and monitor built for the terminal. no packaging, no install wizard, no electron app that opens a browser tab for some reason. clone, install two deps, run. uses scapy for raw packet operations and rich for output. everything is threaded so scans on real subnets are actually fast.

> this is v0.2. a lot more is planned — udp scanning, traceroute, real os fingerprinting, a tui dashboard, alerting, ipv6. treat it accordingly and don't rely on it to pass a pentest certification just yet.

---

## requirements

```
pip install scapy rich
```

most features need root for raw socket access. the tool checks this upfront and tells you exactly what to run instead of just crashing mysteriously.

---

## install

```bash
git clone https://github.com/T9Tuco/project-argus.git
cd project-argus
pip install scapy rich
bash install.sh
```

`install.sh` symlinks `argus` and `argus.py` into `/usr/local/bin` so the command works from anywhere and repo updates are picked up automatically.

---

## usage

run without arguments to get an interactive menu — useful when you don't want to look up flags at 2am:

```
argus
```

or use subcommands directly if you know what you want:

```
sudo argus discover 192.168.1.0/24
sudo argus scan 192.168.1.1
sudo argus ping 8.8.8.8
sudo argus monitor 192.168.1.0/24
```

---

## commands

### discover

arp/icmp sweep to find live hosts on a subnet. useful for "what is even on this network" moments.

```bash
sudo argus discover 192.168.1.0/24
sudo argus discover 10.0.0.0/8 --timeout 3 --retries 2
sudo argus discover 192.168.0.0/24 --json
```

uses arp for private (rfc1918) subnets — fast and doesn't depend on icmp being unfiltered. falls back to a threaded icmp ping sweep if arp returns nothing or the target is remote.

output: ip, mac, avg rtt, os hint (ttl-based), status.

---

### scan

tcp port scan. accepts ips, hostnames, and full urls.

```bash
sudo argus scan 192.168.1.1
sudo argus scan 192.168.1.1 --deep
sudo argus scan 192.168.1.1 -p 22,80,100-200,443
sudo argus scan github.com -b
sudo argus scan https://example.com --json
```

**port specs**

| flag | example | result |
|---|---|---|
| `-p` | `22,80,443` | specific ports |
| `-p` | `100-200` | range |
| `-p` | `22,80,100-200,443` | mixed |
| `--deep` | | all ports 1–1024 |
| _(none)_ | | 26 common ports |

**`-b` / `--banner`** — after finding open ports, connects and reads the first 80 chars of whatever the service says about itself. works for ssh, http, ftp, smtp, etc. some services stay quiet, that's fine too.

**scan modes**

| mode | when | notes |
|---|---|---|
| tcp syn (half-open) | root + scapy | fast, low noise, max 10 workers |
| tcp connect | no root or no scapy | slower, up to 50 workers |

output: port, state (open / filtered), service name, banner, rtt.

---

### ping

icmp echo with per-packet output and a stats summary at the end. basically `ping` but it looks nicer and outputs json if you ask nicely.

```bash
sudo argus ping 8.8.8.8
sudo argus ping 8.8.8.8 -c 20
sudo argus ping google.com --timeout 1
sudo argus ping 1.1.1.1 --json
```

only icmp echo reply (type 0) counts as success. other icmp responses (port unreachable, ttl exceeded, etc.) are correctly counted as loss, not silently ignored.

output: seq / status / rtt per packet, then min / avg / max / jitter / loss summary.

---

### monitor

continuous host monitoring. runs discovery and latency checks on a loop until you tell it to stop.

```bash
sudo argus monitor 192.168.1.0/24
sudo argus monitor 192.168.1.0/24 --interval 60
sudo argus monitor 10.0.0.0/24 -i 10 --timeout 1
```

each sweep discovers live hosts and pings every known host in parallel. hosts that go down stay in the table marked as down — so you can see exactly when your raspberry pi decided to take a nap. stop with `ctrl+c`.

---

## flags

| flag | commands | default | description |
|---|---|---|---|
| `-t` / `--timeout` | all | `2.0` | per-probe timeout in seconds |
| `-r` / `--retries` | discover | `1` | retries per probe |
| `-p` / `--ports` | scan | | port spec: `22,80,100-200,443` |
| `--deep` | scan | off | scan ports 1–1024 |
| `-b` / `--banner` | scan | off | grab banners on open ports |
| `-c` / `--count` | ping | `10` | number of icmp echo requests |
| `-i` / `--interval` | monitor | `30.0` | seconds between sweeps |
| `--json` | discover, scan, ping | off | machine-readable json output |
| `--version` | | | print version and exit |

---

## privileges

| command | needs root | reason |
|---|---|---|
| `discover` | yes | arp and icmp require raw sockets |
| `scan` (syn) | yes | raw tcp packet crafting via scapy |
| `scan` (connect) | no | normal tcp connect() |
| `ping` | yes | raw icmp sockets |
| `monitor` | yes | uses discover and ping internally |

---

## target formats

all commands accept ips, hostnames, and urls:

```bash
argus scan https://github.com    # strips scheme, resolves dns
argus ping google.com            # resolved automatically
argus scan 10.0.0.1              # used as-is
```

`discover` and `monitor` require cidr notation — hostnames are rejected with a clear error message.

---

## json output

```bash
sudo argus discover 192.168.1.0/24 --json | jq '.[] | select(.alive == true)'
sudo argus scan 10.0.0.1 --deep --json | jq '.[] | select(.state == "open")'
sudo argus ping 8.8.8.8 --json | jq '.avg_ms'
```

---

## os fingerprinting

rough guess based on ttl from icmp replies. it's not nmap, but it's something:

| ttl range | guess |
|---|---|
| 1–64 | linux / macos |
| 65–128 | windows |
| 129+ | network device |

proper fingerprinting via tcp stack analysis is on the roadmap.

---

## roadmap

- udp scanning
- traceroute with per-hop latency
- real os fingerprinting via tcp window / options analysis
- service version detection
- exportable reports (json, csv, html)
- tui dashboard
- scheduled monitoring with alerting
- ipv6 support
- config file (`~/.argusrc`)

---

## contributing

pull requests welcome. if something is broken or behaves weirdly, open an issue and describe what happened — "it doesn't work" is not enough information, but you probably already knew that.

---

## license

mit## license

mit
