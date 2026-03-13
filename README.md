# argus

a python-based network scanner and monitor built for the terminal. no packaging wizard, no electron app that opens a browser tab for some reason. clone, install deps, run. uses scapy for raw packets and rich for output that actually looks decent. everything is threaded so real subnet scans don't take until tuesday.

> this is v0.2. a lot more is planned — udp scanning, traceroute, real os fingerprinting, a tui dashboard, alerting, ipv6. treat it accordingly and don't point it at production and yell at me when something breaks.

---

## requirements

```
pip install scapy rich
pip install PySocks   # optional — only needed for --tor mode
```

most features need root for raw socket access. the tool checks this upfront and tells you exactly what to run instead of just crashing with a permission error and no explanation.

---

## install

```bash
git clone https://github.com/T9Tuco/project-argus.git
cd project-argus
pip install scapy rich
bash install.sh
```

`install.sh` symlinks `argus` and `argus.py` into `/usr/local/bin` so the command is available everywhere and repo updates are picked up automatically without reinstalling anything.

---

## usage

run without arguments to get the interactive menu — great for when you just want to click through options at 2am without remembering flags:

```
argus
```

or go straight to a subcommand if you know what you want:

```
sudo argus discover 192.168.1.0/24
sudo argus scan 192.168.1.1
sudo argus scan github.com --tor
sudo argus ping 8.8.8.8
sudo argus monitor 192.168.1.0/24
```

---

## commands

### discover

arp/icmp sweep to find every live host on a subnet. useful for "what is even connected to this network" moments.

```bash
sudo argus discover 192.168.1.0/24
sudo argus discover 10.0.0.0/8 --timeout 3 --retries 2
sudo argus discover 192.168.0.0/24 --json
```

uses arp for rfc1918 subnets — fast and doesn't depend on icmp being unfiltered. falls back to a threaded icmp ping sweep if arp comes back empty or the target is remote.

output: ip, mac, avg rtt, os hint (ttl-based), alive status.

---

### scan

tcp port scan. accepts ips, hostnames, and full urls. supports tor for anonymous scanning (more on that below).

```bash
sudo argus scan 192.168.1.1
sudo argus scan 192.168.1.1 --deep
sudo argus scan 192.168.1.1 -p 22,80,100-200,443
sudo argus scan github.com -b
sudo argus scan https://example.com --json
sudo argus scan 1.2.3.4 --tor
```

**port specs**

| flag | example | what you get |
|---|---|---|
| `-p` | `22,80,443` | those exact ports |
| `-p` | `100-200` | a range |
| `-p` | `22,80,100-200,443` | mixed, why not |
| `--deep` | | all 1–1024 |
| _(nothing)_ | | 26 common ports |

**`-b` / `--banner`** — after finding open ports, connects and reads the first line of whatever the service broadcasts about itself. works for ssh, http, smtp, ftp, etc. some services stay quiet. that's fine.

**scan modes**

| mode | when | notes |
|---|---|---|
| tcp syn (half-open) | root + scapy | fast, low noise, max 10 workers |
| tcp connect | no root / no scapy | slower but works everywhere, up to 50 workers |
| tcp connect via tor | `--tor` flag | anonymous, always connect scan, see below |

output: port, state (open / filtered), service name, banner, rtt.

---

### tor mode

routes the entire scan through the tor network so the target only sees an exit node, not you. every scan thread gets its own circuit via socks5 username/password stream isolation — so the ports aren't all correlated to a single circuit.

**setup:**

```bash
# linux
sudo apt install tor
sudo systemctl start tor

# windows
# install tor browser or the expert bundle, launch it — done
```

if your tor config blocks socks5 auth (some default linux installs do), add this to `/etc/tor/torrc`:
```
SocksPolicy accept 127.0.0.1
```
then `sudo systemctl reload tor`.

**usage:**

```bash
argus scan 1.2.3.4 --tor
argus scan github.com --tor --deep
argus scan 10.0.0.1 --tor -p 22,80,443 -b
```

a few things to know:
- `--tor` forces tcp connect scan. syn scan uses raw sockets which bypass socks proxies entirely and would reveal your ip.
- tor is slow. set `--timeout` to something sensible (4–6s) or expect a lot of false "filtered" results.
- tor requires `PySocks`: `pip install PySocks`. argus checks for it at runtime and tells you if it's missing.
- tor is detected automatically on ports 9050 (system tor) and 9150 (tor browser).

---

### ping

icmp echo with per-packet output and a stats summary. basically `ping` but it looks nicer and outputs json if you ask.

```bash
sudo argus ping 8.8.8.8
sudo argus ping 8.8.8.8 -c 20
sudo argus ping google.com --timeout 1
sudo argus ping 1.1.1.1 --json
```

only icmp type 0 (echo reply) counts as success. other icmp responses are correctly counted as loss, not silently ignored like some tools do.

output: seq / status / rtt per packet, then min / avg / max / jitter / loss at the end.

---

### monitor

continuous host monitoring — runs discovery + latency checks on a loop until you ctrl+c it.

```bash
sudo argus monitor 192.168.1.0/24
sudo argus monitor 192.168.1.0/24 --interval 60
sudo argus monitor 10.0.0.0/24 -i 10 --timeout 1
```

hosts that go down stay in the table marked as dead — so you can see exactly when your raspberry pi decided to reboot itself at 3am. every sweep rediscovers and pings all known hosts in parallel.

---

## flags

| flag | commands | default | description |
|---|---|---|---|
| `-t` / `--timeout` | all | `2.0` | per-probe timeout in seconds |
| `-r` / `--retries` | discover | `1` | retries per probe |
| `-p` / `--ports` | scan | | port spec: `22,80,100-200,443` |
| `--deep` | scan | off | scan ports 1–1024 |
| `-b` / `--banner` | scan | off | grab banners on open ports |
| `--tor` | scan | off | route through tor (needs PySocks + tor running) |
| `-c` / `--count` | ping | `10` | number of icmp requests |
| `-i` / `--interval` | monitor | `30.0` | seconds between sweeps |
| `--json` | discover, scan, ping | off | machine-readable json output |
| `--version` | | | print version and exit |

---

## privileges

| command | needs root | why |
|---|---|---|
| `discover` | yes | arp + icmp need raw sockets |
| `scan` (syn) | yes | raw tcp packet crafting via scapy |
| `scan` (connect) | no | normal tcp connect(), no raw sockets |
| `scan` (tor) | no | connect scan through socks5 proxy |
| `ping` | yes | raw icmp sockets |
| `monitor` | yes | uses discover and ping internally |

---

## target formats

commands accept ips, hostnames, and full urls:

```bash
argus scan https://github.com    # strips scheme, resolves dns
argus ping google.com            # resolved automatically
argus scan 10.0.0.1              # used as-is
```

`discover` and `monitor` need cidr notation — passing a hostname gets rejected with a clear error.

---

## json output

```bash
sudo argus discover 192.168.1.0/24 --json | jq '.[] | select(.alive == true)'
sudo argus scan 10.0.0.1 --deep --json | jq '.[] | select(.state == "open")'
sudo argus ping 8.8.8.8 --json | jq '.avg_ms'
```

---

## os fingerprinting

rough guess based on ttl from icmp replies. not nmap, but better than nothing:

| ttl range | guess |
|---|---|
| 1–64 | linux / macos |
| 65–128 | windows |
| 129+ | network device |

proper fingerprinting via tcp stack analysis is on the roadmap.

---

## version check

argus checks github for a newer release every time it starts. if there's one, it says so. if you're offline or github is down it just stays quiet — no crash, no error, no drama.

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

mit
