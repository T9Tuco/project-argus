#!/usr/bin/env python3
"""
Project Argus — network scanner and monitor.

Usage:
    python argus.py discover <network>
    python argus.py scan <target> [--deep] [-p 22,80,443]
    python argus.py ping <target> [-c 10]
    python argus.py monitor <network>
"""

from __future__ import annotations

import argparse
import ipaddress
import json as json_mod
import os
import platform
import socket
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    from scapy.all import ARP, Ether, IP, ICMP, TCP, sr1, srp, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    console = Console()
except ImportError:
    print("missing dependency: pip install rich")
    sys.exit(1)


# ---------------------------------------------------------------------------
# platform helpers
# ---------------------------------------------------------------------------

def _is_root() -> bool:
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def _bail_no_privs(action: str) -> None:
    if _is_root():
        return
    system = platform.system()
    if system == "Windows":
        hint = "Run the terminal as Administrator."
    elif system == "Darwin":
        hint = "Run with: sudo python argus.py ..."
    else:
        hint = "Run with: sudo python argus.py ..."
    console.print(f"\n[bold red]Need root:[/bold red] {action} requires raw sockets.\n[dim]{hint}[/dim]\n")
    sys.exit(1)


def _is_local(target: str) -> bool:
    for p in ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
              "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
              "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
              "172.30.", "172.31.", "192.168.", "169.254."):
        if target.startswith(p):
            return True
    return False


def _os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return "unknown"
    if ttl <= 64:
        return "Linux/macOS"
    if ttl <= 128:
        return "Windows"
    return "network device"


# ---------------------------------------------------------------------------
# data types
# ---------------------------------------------------------------------------

@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    rtt_ms: list[float] = field(default_factory=list)
    ttl: int = 0
    alive: bool = False

    @property
    def os_hint(self) -> str:
        return _os_from_ttl(self.ttl)

    @property
    def avg_rtt(self) -> float:
        return (sum(self.rtt_ms) / len(self.rtt_ms)) if self.rtt_ms else 0.0

    @property
    def min_rtt(self) -> float:
        return min(self.rtt_ms) if self.rtt_ms else 0.0

    @property
    def max_rtt(self) -> float:
        return max(self.rtt_ms) if self.rtt_ms else 0.0


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    port: int
    state: PortState
    service: str = ""
    rtt_ms: float = 0.0


@dataclass
class LatencyStats:
    ip: str
    sent: int = 0
    received: int = 0
    rtts: list[float] = field(default_factory=list)

    @property
    def loss_pct(self) -> float:
        return ((self.sent - self.received) / self.sent * 100) if self.sent else 100.0

    @property
    def min_ms(self) -> float:
        return min(self.rtts) if self.rtts else 0.0

    @property
    def avg_ms(self) -> float:
        return (sum(self.rtts) / len(self.rtts)) if self.rtts else 0.0

    @property
    def max_ms(self) -> float:
        return max(self.rtts) if self.rtts else 0.0

    @property
    def jitter_ms(self) -> float:
        if len(self.rtts) < 2:
            return 0.0
        diffs = [abs(self.rtts[i] - self.rtts[i - 1]) for i in range(1, len(self.rtts))]
        return sum(diffs) / len(diffs)


# ---------------------------------------------------------------------------
# common ports
# ---------------------------------------------------------------------------

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443, 8888, 27017,
]


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def _arp_sweep(network: str, timeout: float = 2.0) -> list[Host]:
    net = ipaddress.ip_network(network, strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=timeout, retry=0)
    hosts = []
    for sent, recv in answered:
        rtt = (recv.time - sent.sent_time) * 1000
        hosts.append(Host(ip=recv.psrc, mac=recv.hwsrc, rtt_ms=[rtt], alive=True))
    return hosts


def _ping_host(ip: str, timeout: float, retries: int) -> Host:
    host = Host(ip=ip)
    for _ in range(1 + retries):
        pkt = IP(dst=ip) / ICMP()
        start = time.perf_counter()
        reply = sr1(pkt, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        if reply is not None:
            host.alive = True
            host.rtt_ms.append(elapsed)
            host.ttl = reply.ttl
            break
    return host


def _ping_sweep(network: str, timeout: float = 2.0, retries: int = 1) -> list[Host]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = []
    for addr in net.hosts():
        h = _ping_host(str(addr), timeout, retries)
        if h.alive:
            hosts.append(h)
    return hosts


def discover_hosts(network: str, timeout: float = 2.0, retries: int = 1) -> list[Host]:
    if not HAS_SCAPY:
        console.print("[red]scapy not installed — pip install scapy[/red]")
        return []

    hosts: list[Host] = []
    if _is_root() and _is_local(network):
        hosts = _arp_sweep(network, timeout=timeout)
    if not hosts and _is_root():
        hosts = _ping_sweep(network, timeout=timeout, retries=retries)
    return hosts


# ---------------------------------------------------------------------------
# port scanning
# ---------------------------------------------------------------------------

def _resolve_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _syn_scan(target: str, ports: list[int], timeout: float = 2.0) -> list[PortResult]:
    results = []
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        start = time.perf_counter()
        reply = sr1(pkt, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000

        if reply is None:
            state = PortState.FILTERED
        elif reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags & 0x12:  # SYN-ACK
                state = PortState.OPEN
                sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=0.5)
            elif flags & 0x04:  # RST
                state = PortState.CLOSED
            else:
                state = PortState.FILTERED
        else:
            state = PortState.FILTERED

        results.append(PortResult(port=port, state=state, service=_resolve_service(port), rtt_ms=elapsed))
    return results


def _connect_scan(target: str, ports: list[int], timeout: float = 2.0) -> list[PortResult]:
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        state = PortState.FILTERED
        rtt = 0.0
        try:
            start = time.perf_counter()
            sock.connect((target, port))
            rtt = (time.perf_counter() - start) * 1000
            state = PortState.OPEN
        except socket.timeout:
            state = PortState.FILTERED
        except ConnectionRefusedError:
            state = PortState.CLOSED
        except OSError:
            state = PortState.FILTERED
        finally:
            sock.close()
        results.append(PortResult(port=port, state=state, service=_resolve_service(port), rtt_ms=rtt))
    return results


def scan_ports(target: str, ports: list[int] | None = None, deep: bool = False, timeout: float = 2.0) -> list[PortResult]:
    if not HAS_SCAPY and _is_root():
        console.print("[red]scapy not installed — falling back to connect scan[/red]")

    if ports is None:
        ports = list(range(1, 1025)) if deep else TOP_PORTS

    if _is_root() and HAS_SCAPY:
        return _syn_scan(target, ports, timeout=timeout)
    return _connect_scan(target, ports, timeout=timeout)


# ---------------------------------------------------------------------------
# latency
# ---------------------------------------------------------------------------

def measure_latency(target: str, count: int = 10, timeout: float = 2.0, interval: float = 0.5) -> LatencyStats:
    if not HAS_SCAPY:
        console.print("[red]scapy not installed — pip install scapy[/red]")
        return LatencyStats(ip=target)

    stats = LatencyStats(ip=target)
    for seq in range(count):
        pkt = IP(dst=target) / ICMP(seq=seq)
        start = time.perf_counter()
        reply = sr1(pkt, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        stats.sent += 1
        if reply is not None:
            stats.received += 1
            stats.rtts.append(elapsed)
        if seq < count - 1 and interval > 0:
            time.sleep(interval)
    return stats


# ---------------------------------------------------------------------------
# display
# ---------------------------------------------------------------------------

def _banner() -> None:
    # gradient steps from bright cyan down to deep blue-violet
    colors = [
        "#00ffff",
        "#00e5ff",
        "#00c8ff",
        "#00aaff",
        "#008cff",
        "#006fff",
        "#5555ff",
    ]
    lines = [
        r" ______  ____    ____    __  __  ____       ",
        r"/\  _  \/\  _`\ /\  _`\ /\ \/\ \/\  _`\    ",
        r"\ \ \L\ \ \ \L\ \ \ \L\_\ \ \ \ \ \,\L\_\  ",
        r" \ \  __ \ \ ,  /\ \ \L_L\ \ \ \ \/_\__ \  ",
        r"  \ \ \/\ \ \ \\ \\ \ \/, \ \ \_\ \/\ \L\ \",
        r"   \ \_\ \_\ \_\ \_\ \____/\ \_____\ `\____\\",
        r"    \/_/\/_/\/_/\/ /\/___/  \/_____/\/_____/",
    ]
    txt = Text()
    for i, line in enumerate(lines):
        color = colors[min(i, len(colors) - 1)]
        txt.append(line + "\n", style=f"bold {color}")
    txt.append("\n  network scanner & monitor", style="dim")
    console.print(Panel(txt, border_style="#00aaff", padding=(0, 2)))


def _show_hosts(hosts: list[Host]) -> None:
    if not hosts:
        console.print("[yellow]No hosts found.[/yellow]")
        return
    tbl = Table(title="Discovered Hosts", title_style="bold white", border_style="cyan", show_lines=True)
    tbl.add_column("IP", style="bold white", min_width=15)
    tbl.add_column("MAC", style="dim")
    tbl.add_column("RTT (ms)", justify="right")
    tbl.add_column("OS Hint", style="italic")
    tbl.add_column("Status", justify="center")
    for h in sorted(hosts, key=lambda x: x.ip):
        rtt = f"{h.avg_rtt:.1f}" if h.rtt_ms else "—"
        mac = h.mac or "—"
        st = "[green]● up[/green]" if h.alive else "[red]● down[/red]"
        tbl.add_row(h.ip, mac, rtt, h.os_hint, st)
    console.print(tbl)
    console.print(f"[dim]{len(hosts)} host(s) up[/dim]\n")


def _show_scan(target: str, results: list[PortResult]) -> None:
    open_ct = sum(1 for r in results if r.state == PortState.OPEN)
    filt_ct = sum(1 for r in results if r.state == PortState.FILTERED)
    tbl = Table(title=f"Scan — {target}", title_style="bold white", border_style="cyan")
    tbl.add_column("Port", style="bold white", justify="right", min_width=7)
    tbl.add_column("State", min_width=10)
    tbl.add_column("Service", style="dim")
    tbl.add_column("RTT (ms)", justify="right")
    for r in results:
        if r.state == PortState.CLOSED:
            continue
        s = "[green]open[/green]" if r.state == PortState.OPEN else "[yellow]filtered[/yellow]"
        rtt = f"{r.rtt_ms:.1f}" if r.rtt_ms > 0 else "—"
        tbl.add_row(str(r.port), s, r.service or "—", rtt)
    console.print(tbl)
    console.print(f"[dim]{open_ct} open, {filt_ct} filtered, {len(results)} scanned[/dim]\n")


def _show_latency(stats: LatencyStats) -> None:
    tbl = Table(title=f"Latency — {stats.ip}", title_style="bold white", border_style="cyan")
    tbl.add_column("Metric", style="bold")
    tbl.add_column("Value", justify="right")
    tbl.add_row("Sent", str(stats.sent))
    tbl.add_row("Received", str(stats.received))
    c = "green" if stats.loss_pct < 5 else ("yellow" if stats.loss_pct < 30 else "red")
    tbl.add_row("Loss", f"[{c}]{stats.loss_pct:.1f}%[/{c}]")
    tbl.add_row("Min RTT", f"{stats.min_ms:.2f} ms")
    tbl.add_row("Avg RTT", f"{stats.avg_ms:.2f} ms")
    tbl.add_row("Max RTT", f"{stats.max_ms:.2f} ms")
    tbl.add_row("Jitter", f"{stats.jitter_ms:.2f} ms")
    console.print(tbl)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_discover(args: argparse.Namespace) -> None:
    _bail_no_privs("Host discovery")
    _banner()
    with console.status("[bold cyan]Scanning network...[/bold cyan]", spinner="dots"):
        hosts = discover_hosts(args.target, timeout=args.timeout, retries=args.retries)
    if args.json:
        data = [{"ip": h.ip, "mac": h.mac, "rtt_avg_ms": round(h.avg_rtt, 2), "os_hint": h.os_hint} for h in hosts]
        console.print_json(json_mod.dumps(data))
    else:
        _show_hosts(hosts)


def cmd_scan(args: argparse.Namespace) -> None:
    _banner()
    port_list = None
    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            console.print("[red]Bad port list. Use comma-separated numbers.[/red]")
            sys.exit(1)

    method = "SYN" if _is_root() and HAS_SCAPY else "connect"
    total = len(port_list) if port_list else (1024 if args.deep else len(TOP_PORTS))
    console.print(f"[dim]Target: [bold]{args.target}[/bold] | {total} ports | {method} scan[/dim]\n")

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[cyan]Scanning[/cyan]"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("scan", total=total)

        # wrap the scan to get progress updates
        if _is_root() and HAS_SCAPY:
            results = []
            ports = port_list or (list(range(1, 1025)) if args.deep else TOP_PORTS)
            for port in ports:
                r = _syn_scan(args.target, [port], timeout=args.timeout)
                results.extend(r)
                prog.advance(task)
        else:
            results = []
            ports = port_list or (list(range(1, 1025)) if args.deep else TOP_PORTS)
            for port in ports:
                r = _connect_scan(args.target, [port], timeout=args.timeout)
                results.extend(r)
                prog.advance(task)

    if args.json:
        data = [{"port": r.port, "state": r.state.value, "service": r.service, "rtt_ms": round(r.rtt_ms, 2)} for r in results]
        console.print_json(json_mod.dumps(data))
    else:
        _show_scan(args.target, results)


def cmd_ping(args: argparse.Namespace) -> None:
    _bail_no_privs("ICMP ping")
    _banner()

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[cyan]Pinging {task.description}[/cyan]"),
        BarColumn(bar_width=30),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task(args.target, total=args.count)
        stats = LatencyStats(ip=args.target)

        for seq in range(args.count):
            pkt = IP(dst=args.target) / ICMP(seq=seq)
            start = time.perf_counter()
            reply = sr1(pkt, timeout=args.timeout)
            elapsed = (time.perf_counter() - start) * 1000
            stats.sent += 1
            ok = reply is not None
            if ok:
                stats.received += 1
                stats.rtts.append(elapsed)
            prog.advance(task)
            mark = "[green]ok[/green]" if ok else "[red]timeout[/red]"
            console.print(f"  seq={seq + 1}  {mark}  rtt={elapsed:.1f}ms")
            if seq < args.count - 1:
                time.sleep(0.5)

    console.print()
    if args.json:
        data = {"ip": stats.ip, "sent": stats.sent, "received": stats.received,
                "loss_pct": round(stats.loss_pct, 2), "min_ms": round(stats.min_ms, 2),
                "avg_ms": round(stats.avg_ms, 2), "max_ms": round(stats.max_ms, 2),
                "jitter_ms": round(stats.jitter_ms, 2)}
        console.print_json(json_mod.dumps(data))
    else:
        _show_latency(stats)


def cmd_monitor(args: argparse.Namespace) -> None:
    _bail_no_privs("Network monitoring")
    _banner()
    console.print(f"[dim]Monitoring [bold]{args.target}[/bold] every {args.interval}s — Ctrl+C to stop[/dim]\n")

    known: dict[str, Host] = {}
    sweep = 0
    try:
        while True:
            sweep += 1
            console.rule(f"[cyan]sweep #{sweep}[/cyan]")
            with console.status("[cyan]Discovering...[/cyan]", spinner="dots"):
                hosts = discover_hosts(args.target, timeout=args.timeout)
            for h in hosts:
                known[h.ip] = h

            # quick latency check
            if known:
                for ip in list(known):
                    st = measure_latency(ip, count=3, timeout=args.timeout, interval=0.2)
                    if st.rtts:
                        known[ip].rtt_ms = st.rtts
                        known[ip].alive = True
                    else:
                        known[ip].alive = False

            _show_hosts(list(known.values()))
            console.print(f"[dim]next sweep in {args.interval}s...[/dim]\n")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")


# ---------------------------------------------------------------------------
# arg parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="argus", description="Network scanner and monitor.")
    p.add_argument("--version", action="version", version="argus 0.1.0")
    sub = p.add_subparsers(dest="command")

    # discover
    d = sub.add_parser("discover", help="ARP/ICMP host discovery")
    d.add_argument("target", help="Network in CIDR notation (e.g. 192.168.1.0/24)")
    d.add_argument("-t", "--timeout", type=float, default=2.0)
    d.add_argument("-r", "--retries", type=int, default=1)
    d.add_argument("--json", action="store_true")

    # scan
    s = sub.add_parser("scan", help="TCP port scan")
    s.add_argument("target", help="Target IP address")
    s.add_argument("-p", "--ports", help="Comma-separated ports")
    s.add_argument("--deep", action="store_true", help="Scan 1-1024")
    s.add_argument("-t", "--timeout", type=float, default=2.0)
    s.add_argument("--json", action="store_true")

    # ping
    pg = sub.add_parser("ping", help="ICMP ping with latency stats")
    pg.add_argument("target", help="Target IP address")
    pg.add_argument("-c", "--count", type=int, default=10)
    pg.add_argument("-t", "--timeout", type=float, default=2.0)
    pg.add_argument("--json", action="store_true")

    # monitor
    m = sub.add_parser("monitor", help="Continuous network monitoring")
    m.add_argument("target", help="Network in CIDR notation")
    m.add_argument("-i", "--interval", type=float, default=30.0)
    m.add_argument("-t", "--timeout", type=float, default=2.0)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "discover": cmd_discover,
        "scan": cmd_scan,
        "ping": cmd_ping,
        "monitor": cmd_monitor,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
