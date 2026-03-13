
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json as json_mod
import os
import platform
import random
import socket
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from threading import local as thread_local
from typing import Optional

# scapy is optional, falls back to connect scan if missing
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
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    console = Console()
except ImportError:
    print("missing dependency: pip install rich")
    sys.exit(1)

# PySocks is optional, only needed for --tor mode
try:
    import socks as _socks_mod
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

MAX_THREADS = 50
ARGUS_VERSION = "0.2.0"


def _check_version() -> Optional[str]:
    # fetch latest release tag from GitHub, return it if newer than ARGUS_VERSION
    try:
        url = "https://api.github.com/repos/T9Tuco/project-argus/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "argus-version-check"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json_mod.loads(resp.read().decode())
        tag = data.get("tag_name", "").lstrip("v")
        if not tag:
            return None
        # compare as tuples so "0.3.0" > "0.2.0"
        def _ver(s: str):
            try:
                return tuple(int(x) for x in s.split("."))
            except ValueError:
                return (0,)
        if _ver(tag) > _ver(ARGUS_VERSION):
            return tag
    except Exception:
        pass
    return None


_real_socket = socket.socket


def _tor_identity() -> str:
    if not hasattr(_tor_thread_data, "identity"):
        _tor_thread_data.identity = str(random.randint(1, 999_999_999))
    return _tor_thread_data.identity


def _tor_rotate() -> None:
    _tor_thread_data.identity = str(random.randint(1, 999_999_999))


def _tor_check(port: int) -> bool:
    # always use the real socket here, even if patching is already active
    try:
        s = _real_socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except OSError:
        return False


def _tor_find_port() -> Optional[int]:
    for port in (9050, 9150):
        if _tor_check(port):
            return port
    return None


def _tor_patch_socket(tor_port: int) -> None:
    if not HAS_SOCKS:
        console.print("[red]PySocks not installed — pip install PySocks[/red]")
        sys.exit(1)

    current_port = tor_port

    class _TorSocket(_socks_mod.socksocket):
        def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None):
            super().__init__(family, type, proto, _sock)
            ident = _tor_identity()
            self.set_proxy(
                _socks_mod.SOCKS5,
                "127.0.0.1",
                current_port,
                True,
                username=ident,
                password=ident,
            )

    socket.socket = _TorSocket


def _tor_unpatch_socket() -> None:
    socket.socket = _real_socket



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
    else:
        hint = "Run with: sudo argus ..."
    console.print(f"\n[bold red]Need root:[/bold red] {action} requires raw sockets.\n[dim]{hint}[/dim]\n")
    sys.exit(1)


def _resolve_target(raw: str, expect_network: bool = False) -> str:
    # strip scheme if someone pastes a full URL
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.hostname or raw
    else:
        raw = raw.strip()

    if expect_network:
        try:
            ipaddress.ip_network(raw, strict=False)
            return raw
        except ValueError:
            pass
        console.print(f"[bold red]Invalid target:[/bold red] [white]{raw!r}[/white] is not a valid CIDR range.\n"
                      f"[dim]Examples: 192.168.1.0/24, 10.0.0.0/8[/dim]")
        sys.exit(1)

    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass

    # not an IP, try DNS
    try:
        resolved = socket.gethostbyname(raw)
        console.print(f"[dim]{raw} -> {resolved}[/dim]")
        return resolved
    except socket.gaierror:
        console.print(f"[bold red]Invalid target:[/bold red] [white]{raw!r}[/white] not an IP and DNS lookup failed.")
        sys.exit(1)


def _is_local(target: str) -> bool:
    # only sweep with ARP on private networks, not across the internet
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.is_private and not net.is_loopback
    except ValueError:
        try:
            return ipaddress.ip_address(target).is_private
        except ValueError:
            return False


def _os_from_ttl(ttl: int) -> str:
    # rough OS guess based on default TTL values
    if ttl <= 0:
        return "unknown"
    if ttl <= 64:
        return "Linux/macOS"
    if ttl <= 128:
        return "Windows"
    return "network device"


def _parse_ports(spec: str) -> list[int]:
    # accepts "22,80,100-200,443" style input
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                lo, hi = int(lo), int(hi)
                if lo > hi or lo < 1 or hi > 65535:
                    console.print(f"[red]Bad port range: {part}[/red]")
                    sys.exit(1)
                ports.extend(range(lo, hi + 1))
            except ValueError:
                console.print(f"[red]Bad port range: {part}[/red]")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError
                ports.append(p)
            except ValueError:
                console.print(f"[red]Bad port: {part}[/red]")
                sys.exit(1)
    return sorted(set(ports))


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
    banner: str = ""


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


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443, 8888, 27017,
]


def _arp_sweep(network: str, timeout: float = 2.0) -> list[Host]:
    net = ipaddress.ip_network(network, strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=timeout, retry=0)
    hosts = []
    for sent, recv in answered:
        rtt = (recv.time - sent.sent_time) * 1000
        hosts.append(Host(ip=recv.psrc, mac=recv.hwsrc, rtt_ms=[rtt], alive=True))
    return hosts


def _ping_one(ip: str, timeout: float, retries: int) -> Optional[Host]:
    host = Host(ip=ip)
    for _ in range(1 + retries):
        pkt = IP(dst=ip) / ICMP()
        start = time.perf_counter()
        reply = sr1(pkt, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        if reply is not None and reply.haslayer(ICMP) and reply[ICMP].type == 0:
            host.alive = True
            host.rtt_ms.append(elapsed)
            host.ttl = reply.ttl
            return host
    return None


def _ping_sweep_threaded(network: str, timeout: float = 2.0, retries: int = 1) -> list[Host]:
    net = ipaddress.ip_network(network, strict=False)
    addrs = [str(a) for a in net.hosts()]
    hosts: list[Host] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        futures = {pool.submit(_ping_one, ip, timeout, retries): ip for ip in addrs}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result.alive:
                hosts.append(result)
    return hosts


def discover_hosts(network: str, timeout: float = 2.0, retries: int = 1) -> list[Host]:
    # tries ARP first (LAN only), falls back to ICMP ping sweep
    if not HAS_SCAPY:
        console.print("[red]scapy not installed — pip install scapy[/red]")
        return []

    hosts: list[Host] = []
    if _is_root() and _is_local(network):
        hosts = _arp_sweep(network, timeout=timeout)
    if not hosts and _is_root():
        hosts = _ping_sweep_threaded(network, timeout=timeout, retries=retries)
    return hosts


def _resolve_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    # connect and read the first bytes the service sends back
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"\r\n")
        data = s.recv(256)
        s.close()
        return data.decode("utf-8", errors="replace").strip()[:80]
    except Exception:
        return ""


def _scan_single_syn(target: str, port: int, timeout: float) -> PortResult:
    # SYN scan: send SYN, read reply flags, send RST to close the half-open connection
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    start = time.perf_counter()
    reply = sr1(pkt, timeout=timeout)
    elapsed = (time.perf_counter() - start) * 1000

    if reply is None:
        state = PortState.FILTERED
    elif reply.haslayer(TCP):
        flags = int(reply[TCP].flags)
        if (flags & 0x02) and not (flags & 0x04):  # SYN-ACK
            state = PortState.OPEN
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=0.5)
        elif flags & 0x04:  # RST
            state = PortState.CLOSED
        else:
            state = PortState.FILTERED
    else:
        state = PortState.FILTERED

    return PortResult(port=port, state=state, service=_resolve_service(port), rtt_ms=elapsed)


def _scan_single_connect(target: str, port: int, timeout: float) -> PortResult:
    # unprivileged fallback using a full TCP connect
    # if socket is patched via _tor_patch_socket(), this transparently goes through Tor
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
    return PortResult(port=port, state=state, service=_resolve_service(port), rtt_ms=rtt)


def scan_ports_threaded(target: str, ports: list[int], timeout: float = 2.0,
                        progress_cb=None, force_connect: bool = False) -> list[PortResult]:
    # SYN scan needs root and scapy, otherwise falls back to connect scan
    # force_connect=True is used when routing through Tor (raw sockets don't go through SOCKS)
    use_syn = _is_root() and HAS_SCAPY and not force_connect
    scan_fn = _scan_single_syn if use_syn else _scan_single_connect
    results: list[PortResult] = []

    # lower worker count for SYN to avoid flooding the network
    workers = min(10, len(ports)) if use_syn else min(MAX_THREADS, len(ports))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(scan_fn, target, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(future_map):
            r = future.result()
            results.append(r)
            if progress_cb:
                progress_cb(r)

    results.sort(key=lambda r: r.port)
    return results


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
        if reply is not None and reply.haslayer(ICMP) and reply[ICMP].type == 0:
            stats.received += 1
            stats.rtts.append(elapsed)
        if seq < count - 1 and interval > 0:
            time.sleep(interval)
    return stats


def _banner() -> None:
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
        " ______  ____    ____    __  __  ____       ",
        "/\\  _  \\/\\  _`\\ /\\  _`\\ /\\ \\/\\ \\/\\  _`\\    ",
        "\\ \\ \\L\\ \\ \\ \\L\\ \\ \\ \\L\\_\\ \\ \\ \\ \\ \\,\\L\\_\\  ",
        " \\ \\  __ \\ \\ ,  /\\ \\ \\L_L\\ \\ \\ \\ \\/_\\__ \\  ",
        "  \\ \\ \\/\\ \\ \\ \\\\ \\\\ \\ \\/, \\ \\ \\_\\ \\/\\ \\L\\ \\",
        "   \\ \\_\\ \\_\\ \\_\\ \\_\\ \\____/\\ \\_____\\ `\\____\\",
        "    \\/_/\\/_/\\/_/\\/ /\\/___/  \\/_____/\\/_____/",
        "      made by TucoT9 | github.com/t9tuco/project-argus",
    ]
    txt = Text()
    for i, line in enumerate(lines):
        color = colors[min(i, len(colors) - 1)]
        txt.append(line + "\n", style=f"bold {color}")
    txt.append(f"\n  network scanner & monitor  v{ARGUS_VERSION}", style="dim")
    console.print(Panel(txt, border_style="#00aaff", padding=(0, 2)))

    # non-blocking version check — if it fails (offline, etc.) just skip it
    new_ver = _check_version()
    if new_ver:
        console.print(f"  [yellow]update available: v{new_ver} — github.com/T9Tuco/project-argus[/yellow]\n")


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
    for h in sorted(hosts, key=lambda x: ipaddress.ip_address(x.ip)):
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
    tbl.add_column("Banner", style="dim italic", max_width=40)
    tbl.add_column("RTT (ms)", justify="right")
    for r in results:
        if r.state == PortState.CLOSED:
            continue
        s = "[green]open[/green]" if r.state == PortState.OPEN else "[yellow]filtered[/yellow]"
        rtt = f"{r.rtt_ms:.1f}" if r.rtt_ms > 0 else "—"
        tbl.add_row(str(r.port), s, r.service or "—", r.banner or "—", rtt)
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


def _interactive() -> None:
    _banner()
    priv = "[green]root[/green]" if _is_root() else "[red]unprivileged[/red]"
    tor_status = "[green]ok[/green]" if HAS_SOCKS else "[red]missing (pip install PySocks)[/red]"
    console.print(f"  [dim]running as {priv} | scapy {'[green]ok[/green]' if HAS_SCAPY else '[red]missing[/red]'} | tor {tor_status}[/dim]\n")

    while True:
        console.print("[bold cyan]What do you want to do?[/bold cyan]\n")
        console.print("  [bold white]1[/bold white]  Discover hosts on a network")
        console.print("  [bold white]2[/bold white]  Scan ports on a host")
        console.print("  [bold white]3[/bold white]  Scan ports via Tor  [dim](anonymous — needs PySocks + Tor on 9050/9150)[/dim]")
        console.print("  [bold white]4[/bold white]  Ping a host (latency stats)")
        console.print("  [bold white]5[/bold white]  Monitor a network (continuous)")
        console.print("  [bold white]6[/bold white]  Exit")
        console.print()

        choice = Prompt.ask("[cyan]>[/cyan]", choices=["1", "2", "3", "4", "5", "6"], default="6")

        if choice == "1":
            _interactive_discover()
        elif choice == "2":
            _interactive_scan(use_tor=False)
        elif choice == "3":
            _interactive_scan(use_tor=True)
        elif choice == "4":
            _interactive_ping()
        elif choice == "5":
            _interactive_monitor()
        else:
            console.print("[dim]bye.[/dim]")
            break

        console.print()
        if not Confirm.ask("[dim]Run another command?[/dim]", default=True):
            console.print("[dim]bye.[/dim]")
            break
        console.print()


def _interactive_discover() -> None:
    target = Prompt.ask("\n[cyan]Network (CIDR)[/cyan]", default="192.168.1.0/24")
    target = _resolve_target(target, expect_network=True)

    if not _is_root():
        console.print("[red]Discovery needs root. Restart with sudo.[/red]")
        return

    timeout = float(Prompt.ask("[cyan]Timeout (sec)[/cyan]", default="2"))
    retries = int(Prompt.ask("[cyan]Retries[/cyan]", default="1"))

    with console.status("[bold cyan]Scanning network...[/bold cyan]", spinner="dots"):
        hosts = discover_hosts(target, timeout=timeout, retries=retries)
    _show_hosts(hosts)


def _interactive_scan(use_tor: bool = False) -> None:
    target = Prompt.ask("\n[cyan]Target (IP, hostname, or URL)[/cyan]")
    target = _resolve_target(target, expect_network=False)

    console.print("\n[bold cyan]Scan type:[/bold cyan]")
    console.print("  [white]1[/white]  Common ports (26 ports)")
    console.print("  [white]2[/white]  Deep scan (1–1024)")
    console.print("  [white]3[/white]  Custom port list")
    scan_type = Prompt.ask("[cyan]>[/cyan]", choices=["1", "2", "3"], default="1")

    if scan_type == "3":
        port_spec = Prompt.ask("[cyan]Ports (e.g. 22,80,100-200,443)[/cyan]")
        ports = _parse_ports(port_spec)
    elif scan_type == "2":
        ports = list(range(1, 1025))
    else:
        ports = TOP_PORTS

    timeout = float(Prompt.ask("[cyan]Timeout (sec)[/cyan]", default="2"))
    grab = Confirm.ask("[cyan]Grab banners on open ports?[/cyan]", default=False)

    # only ask if caller didn't already decide
    if not use_tor:
        use_tor = Confirm.ask("[cyan]Route through Tor?[/cyan]", default=False)

    if use_tor:
        if not HAS_SOCKS:
            console.print("[red]Tor mode requires PySocks: pip install PySocks[/red]")
            return
        tor_port = _tor_find_port()
        if tor_port is None:
            console.print("[red]Tor not detected on ports 9050 or 9150. Start Tor first.[/red]")
            if platform.system() != "Windows":
                console.print("[dim]Linux: sudo systemctl start tor[/dim]")
                console.print("[dim]Also add 'SocksPolicy accept 127.0.0.1' to /etc/tor/torrc if circuit isolation fails.[/dim]")
            return
        _tor_patch_socket(tor_port)
        console.print(f"[dim]Tor active on port {tor_port} | circuit isolation per thread[/dim]")

    method = "connect (via Tor)" if use_tor else ("SYN" if _is_root() and HAS_SCAPY else "connect")
    console.print(f"\n[dim]{len(ports)} ports | {method} scan[/dim]\n")

    results: list[PortResult] = []
    with Progress(
        SpinnerColumn("dots"), TextColumn("[cyan]Scanning[/cyan]"),
        BarColumn(bar_width=40), TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(), console=console,
    ) as prog:
        task = prog.add_task("scan", total=len(ports))

        def on_result(r: PortResult) -> None:
            results.append(r)
            prog.advance(task)

        scan_ports_threaded(target, ports, timeout=timeout, progress_cb=on_result,
                            force_connect=use_tor)

    if grab:
        open_results = [r for r in results if r.state == PortState.OPEN]
        if open_results:
            with console.status("[cyan]Grabbing banners...[/cyan]", spinner="dots"):
                for r in open_results:
                    r.banner = _grab_banner(target, r.port, timeout=timeout)

    results.sort(key=lambda r: r.port)
    _show_scan(target, results)


def _interactive_ping() -> None:
    target = Prompt.ask("\n[cyan]Target (IP, hostname, or URL)[/cyan]")
    target = _resolve_target(target, expect_network=False)

    if not _is_root() or not HAS_SCAPY:
        console.print("[red]Ping needs root and scapy. Restart with sudo.[/red]")
        return

    count = int(Prompt.ask("[cyan]Ping count[/cyan]", default="10"))
    timeout = float(Prompt.ask("[cyan]Timeout (sec)[/cyan]", default="2"))

    with Progress(
        SpinnerColumn("dots"), TextColumn("[cyan]Pinging[/cyan]"),
        BarColumn(bar_width=30), TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(), console=console,
    ) as prog:
        task = prog.add_task(target, total=count)
        stats = LatencyStats(ip=target)

        for seq in range(count):
            pkt = IP(dst=target) / ICMP(seq=seq)
            start = time.perf_counter()
            reply = sr1(pkt, timeout=timeout)
            elapsed = (time.perf_counter() - start) * 1000
            stats.sent += 1
            ok = reply is not None and reply.haslayer(ICMP) and reply[ICMP].type == 0
            if ok:
                stats.received += 1
                stats.rtts.append(elapsed)
            prog.advance(task)
            mark = "[green]ok[/green]" if ok else "[red]timeout[/red]"
            console.print(f"  seq={seq + 1}  {mark}  rtt={elapsed:.1f}ms")
            if seq < count - 1:
                time.sleep(0.5)

    console.print()
    _show_latency(stats)


def _interactive_monitor() -> None:
    target = Prompt.ask("\n[cyan]Network (CIDR)[/cyan]", default="192.168.1.0/24")
    target = _resolve_target(target, expect_network=True)

    if not _is_root():
        console.print("[red]Monitoring needs root. Restart with sudo.[/red]")
        return

    interval = float(Prompt.ask("[cyan]Interval between sweeps (sec)[/cyan]", default="30"))
    timeout = float(Prompt.ask("[cyan]Timeout (sec)[/cyan]", default="2"))

    console.print(f"\n[dim]Monitoring [bold]{target}[/bold] every {interval}s — Ctrl+C to stop[/dim]\n")
    known: dict[str, Host] = {}
    sweep = 0
    try:
        while True:
            sweep += 1
            console.rule(f"[cyan]sweep #{sweep}[/cyan]")
            with console.status("[cyan]Discovering...[/cyan]", spinner="dots"):
                hosts = discover_hosts(target, timeout=timeout)
            for h in hosts:
                known[h.ip] = h

            if known:
                with console.status("[cyan]Checking latency...[/cyan]", spinner="dots"):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
                        futures = {pool.submit(measure_latency, ip, 3, timeout, 0.2): ip for ip in known}
                        for f in concurrent.futures.as_completed(futures):
                            ip = futures[f]
                            st = f.result()
                            if st.rtts:
                                known[ip].rtt_ms = st.rtts
                                known[ip].alive = True
                            else:
                                known[ip].alive = False

            _show_hosts(list(known.values()))
            console.print(f"[dim]next sweep in {interval}s...[/dim]\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")


def cmd_discover(args: argparse.Namespace) -> None:
    args.target = _resolve_target(args.target, expect_network=True)
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
    args.target = _resolve_target(args.target, expect_network=False)

    if args.tor:
        if not HAS_SOCKS:
            console.print("[red]--tor requires PySocks: pip install PySocks[/red]")
            sys.exit(1)
        tor_port = _tor_find_port()
        if tor_port is None:
            console.print("[red]Tor not detected on ports 9050 or 9150. Start Tor first.[/red]")
            if platform.system() != "Windows":
                console.print("[dim]Linux: sudo systemctl start tor[/dim]")
                console.print("[dim]Also add 'SocksPolicy accept 127.0.0.1' to /etc/tor/torrc if circuit isolation fails.[/dim]")
            sys.exit(1)
        _tor_patch_socket(tor_port)
        console.print(f"[dim]Tor active on port {tor_port} | circuit isolation per thread[/dim]")

    port_list = None
    if args.ports:
        port_list = _parse_ports(args.ports)

    ports = port_list or (list(range(1, 1025)) if args.deep else TOP_PORTS)
    method = "SYN" if _is_root() and HAS_SCAPY and not args.tor else "connect"
    if args.tor:
        method = "connect (via Tor)"
    console.print(f"[dim]Target: [bold]{args.target}[/bold] | {len(ports)} ports | {method} scan[/dim]\n")

    results: list[PortResult] = []
    with Progress(
        SpinnerColumn("dots"), TextColumn("[cyan]Scanning[/cyan]"),
        BarColumn(bar_width=40), TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(), console=console,
    ) as prog:
        task = prog.add_task("scan", total=len(ports))

        def on_result(r: PortResult) -> None:
            results.append(r)
            prog.advance(task)

        scan_ports_threaded(args.target, ports, timeout=args.timeout, progress_cb=on_result,
                            force_connect=args.tor)

    if args.banner:
        open_results = [r for r in results if r.state == PortState.OPEN]
        if open_results:
            with console.status("[cyan]Grabbing banners...[/cyan]", spinner="dots"):
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
                    futures = {pool.submit(_grab_banner, args.target, r.port, args.timeout): r for r in open_results}
                    for f in concurrent.futures.as_completed(futures):
                        r = futures[f]
                        r.banner = f.result()

    results.sort(key=lambda r: r.port)
    if args.json:
        data = [{"port": r.port, "state": r.state.value, "service": r.service,
                 "banner": r.banner, "rtt_ms": round(r.rtt_ms, 2)} for r in results]
        console.print_json(json_mod.dumps(data))
    else:
        _show_scan(args.target, results)


def cmd_ping(args: argparse.Namespace) -> None:
    args.target = _resolve_target(args.target, expect_network=False)
    _bail_no_privs("ICMP ping")
    if not HAS_SCAPY:
        console.print("[red]scapy not installed — pip install scapy[/red]")
        sys.exit(1)
    _banner()

    with Progress(
        SpinnerColumn("dots"), TextColumn("[cyan]Pinging {task.description}[/cyan]"),
        BarColumn(bar_width=30), TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(), console=console,
    ) as prog:
        task = prog.add_task(args.target, total=args.count)
        stats = LatencyStats(ip=args.target)

        for seq in range(args.count):
            pkt = IP(dst=args.target) / ICMP(seq=seq)
            start = time.perf_counter()
            reply = sr1(pkt, timeout=args.timeout)
            elapsed = (time.perf_counter() - start) * 1000
            stats.sent += 1
            ok = reply is not None and reply.haslayer(ICMP) and reply[ICMP].type == 0
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
    args.target = _resolve_target(args.target, expect_network=True)
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

            if known:
                with console.status("[cyan]Checking latency...[/cyan]", spinner="dots"):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
                        futures = {pool.submit(measure_latency, ip, 3, args.timeout, 0.2): ip for ip in known}
                        for f in concurrent.futures.as_completed(futures):
                            ip = futures[f]
                            st = f.result()
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


def build_parser() -> argparse.ArgumentParser:
    top_epilog = (
        "Tor anonymous scanning:\n"
        "  argus scan <target> --tor\n"
        "\n"
        "  requires: pip install PySocks  +  Tor running on port 9050 or 9150\n"
        "  Linux:    sudo apt install tor && sudo systemctl start tor\n"
        "  Windows:  install Tor Browser or Expert Bundle and launch it\n"
        "\n"
        "  run 'argus scan --help' for full Tor usage and examples."
    )
    p = argparse.ArgumentParser(
        prog="argus",
        description="Network scanner and monitor. Run without arguments for interactive mode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=top_epilog,
    )
    p.add_argument("--version", action="version", version=f"argus {ARGUS_VERSION}")
    sub = p.add_subparsers(dest="command")

    d = sub.add_parser("discover", help="ARP/ICMP host discovery")
    d.add_argument("target", help="Network in CIDR notation (e.g. 192.168.1.0/24)")
    d.add_argument("-t", "--timeout", type=float, default=2.0)
    d.add_argument("-r", "--retries", type=int, default=1)
    d.add_argument("--json", action="store_true")

    scan_epilog = (
        "Tor mode routes the scan anonymously through the Tor network.\n"
        "Requirements: pip install PySocks  +  Tor running (port 9050 or 9150)\n"
        "\n"
        "  Linux:   sudo apt install tor && sudo systemctl start tor\n"
        "  Windows: install Tor Browser or Expert Bundle, launch it first\n"
        "\n"
        "Examples:\n"
        "  argus scan 1.2.3.4 --tor\n"
        "  argus scan github.com --tor --deep\n"
        "  argus scan 10.0.0.1 --tor -p 22,80,443 -b\n"
        "\n"
        "Note: --tor forces TCP connect scan (SYN scan bypasses SOCKS proxies).\n"
        "      Each scan thread gets its own Tor circuit for stream isolation."
    )
    s = sub.add_parser(
        "scan",
        help="TCP port scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=scan_epilog,
    )
    s.add_argument("target", help="Target IP, hostname, or URL")
    s.add_argument("-p", "--ports", help="Ports: 22,80,100-200,443")
    s.add_argument("--deep", action="store_true", help="Scan ports 1-1024 instead of common ports")
    s.add_argument("-t", "--timeout", type=float, default=2.0, help="Per-port timeout in seconds (default: 2.0)")
    s.add_argument("-b", "--banner", action="store_true", help="Grab banners on open ports")
    s.add_argument("--tor", action="store_true", help="Route scan through Tor (requires PySocks + Tor running on 9050/9150)")
    s.add_argument("--json", action="store_true")

    pg = sub.add_parser("ping", help="ICMP ping with latency stats")
    pg.add_argument("target", help="Target IP, hostname, or URL")
    pg.add_argument("-c", "--count", type=int, default=10)
    pg.add_argument("-t", "--timeout", type=float, default=2.0)
    pg.add_argument("--json", action="store_true")

    m = sub.add_parser("monitor", help="Continuous network monitoring")
    m.add_argument("target", help="Network in CIDR notation")
    m.add_argument("-i", "--interval", type=float, default=30.0)
    m.add_argument("-t", "--timeout", type=float, default=2.0)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        _interactive()
        return

    dispatch = {
        "discover": cmd_discover,
        "scan": cmd_scan,
        "ping": cmd_ping,
        "monitor": cmd_monitor,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()

