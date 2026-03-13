# project argus

this is early. there's a lot more planned — proper os fingerprinting, udp scanning, traceroute, export formats, a tui dashboard, scheduled monitoring with alerting, ipv6. treat this as v0.2 of something that's going to keep growing for a while.
```
note: its really buggy atm, you can make pull request if you want to help me :)
```
---

a python-based network scanner and monitor. no packaging, no install step — clone, install two deps, done. uses scapy for raw packet operations and rich for terminal output. everything is threaded so scans on real-sized subnets are actually fast.

## dependencies

```
pip install scapy rich
```

most features need root/admin for raw socket access. the tool checks this upfront and tells you what to run.

## install as system command

```bash
git clone https://github.com/T9Tuco/project-argus.git
cd project-argus
pip install scapy rich
sudo ln -sf "$PWD/argus.py" /usr/local/bin/argus.py
sudo ln -sf "$PWD/argus" /usr/local/bin/argus
sudo chmod +x /usr/local/bin/argus
```

after that, `argus` works from anywhere. or just use the included script:

```bash
bash install.sh
```

---

## interactive mode

run `argus` with no arguments to get a menu-driven interface — no need to remember commands:

```
argus
```

you'll get a numbered menu to pick what you want to do, then it asks for the target, options, etc. step by step. good for quick one-off scans without looking up flags.

---

## commands

### discover

arp/icmp sweep to find live hosts on a subnet. parallel on large ranges.

```
sudo argus discover 192.168.1.0/24
sudo argus discover 10.0.0.0/8 --timeout 3 --retries 2
sudo argus discover 192.168.0.0/24 --json
```

uses arp for local (rfc1918) subnets — fast and doesn't depend on icmp being unfiltered. falls back to threaded icmp ping sweep for remote subnets or if arp returns nothing.

output: ip, mac, avg rtt, os hint (ttl-based), status.

---

### scan

tcp port scan. accepts ips, hostnames, and full urls.

```
sudo argus scan 192.168.1.1
sudo argus scan 192.168.1.1 --deep
sudo argus scan 192.168.1.1 -p 22,80,100-200,443
sudo argus scan github.com -b
sudo argus scan https://example.com --json
```

**port specs:**
- `-p 22,80,443` — specific ports
- `-p 100-200` — range
- `-p 22,80,100-200,443` — mix
- `--deep` — all ports 1–1024

**`-b` / `--banner`** — after finding open ports, connects and reads the first 80 chars of the service response. works for ssh, http, ftp, smtp etc.

**scan modes:**
- with root + scapy: tcp syn (half-open). fast, low-noise.
- without root: tcp connect(). slower, but no privileges needed.

both modes are threaded. syn scan uses up to 10 parallel workers (scapy shared-socket limitation), connect scan up to 50.

output: port, state (open/filtered), service name, banner, rtt.

---

### ping

icmp echo with per-packet output and a stats summary.

```
sudo argus ping 8.8.8.8
sudo argus ping 8.8.8.8 -c 20
sudo argus ping google.com --timeout 1
sudo argus ping 1.1.1.1 --json
```

only counts icmp echo reply (type 0) as success — "port unreachable" and other icmp error responses are correctly counted as failures.

output: per-packet seq/status/rtt, then min/avg/max rtt, jitter, packet loss.

---

### monitor

continuous network monitoring. runs discover + latency checks in a loop.

```
sudo argus monitor 192.168.1.0/24
sudo argus monitor 192.168.1.0/24 --interval 60
sudo argus monitor 10.0.0.0/24 -i 10 --timeout 1
```

each sweep: finds all live hosts, then pings each known host in parallel to update rtt and alive status. hosts that go down stay in the table marked as down so you can see the change.

---

## all flags

| flag | commands | default | description |
|---|---|---|---|
| `-t` / `--timeout` | all | `2.0` | per-probe timeout in seconds |
| `-r` / `--retries` | discover | `1` | retries per probe |
| `--deep` | scan | off | scan ports 1–1024 |
| `-p` / `--ports` | scan | — | port spec: `22,80,100-200,443` |
| `-b` / `--banner` | scan | off | grab service banners on open ports |
| `-c` / `--count` | ping | `10` | number of icmp echo requests |
| `-i` / `--interval` | monitor | `30.0` | seconds between sweeps |
| `--json` | discover, scan, ping | off | json output |
| `--version` | — | — | print version and exit |

---

## privileges

| command | needs root | why |
|---|---|---|
| `discover` | yes | arp and icmp need raw sockets |
| `scan` (syn) | yes | raw tcp packet crafting |
| `scan` (connect) | no | uses normal tcp connect() |
| `ping` | yes | raw icmp sockets |
| `monitor` | yes | uses discover + ping internally |

---

## target input

all commands accept ips, hostnames, and urls:

```
argus scan https://github.com       # strips to github.com, resolves dns
argus ping google.com               # dns resolved automatically
argus scan 10.0.0.1                 # used as-is
```

`discover` and `monitor` require cidr notation — hostnames are rejected with a clear message.

---

## json output

```bash
sudo argus discover 192.168.1.0/24 --json | jq '.[] | select(.alive == true)'
sudo argus scan 10.0.0.1 --deep --json | jq '.[] | select(.state == "open")'
sudo argus ping 8.8.8.8 --json | jq '.avg_ms'
```

---

## os fingerprinting

rough guess based on ip ttl from icmp replies:

| ttl range | guess |
|---|---|
| 1–64 | linux / macos |
| 65–128 | windows |
| 129+ | network device |

proper fingerprinting (tcp window size, options analysis) is on the roadmap.

---

## what's coming

- udp scanning
- traceroute with per-hop latency
- real os fingerprinting via tcp stack analysis
- service version detection improvements
- exportable reports (json, csv, html)
- tui dashboard (textual)
- scheduled monitoring with alerting
- ipv6 support
- config file (~/.argusrc)

---

## license

mit
