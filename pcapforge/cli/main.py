"""
PCAPForge CLI

Commands:
  pcapforge analyze <file.pcap>   -- full forensic analysis
  pcapforge flows <file.pcap>     -- show top flows only
  pcapforge dns <file.pcap>       -- DNS analysis only
  pcapforge demo                  -- analyze synthetic PCAP

Usage:
  pcapforge analyze capture.pcap
  pcapforge analyze capture.pcap --no-ai --output report.html
  pcapforge flows capture.pcap
  pcapforge dns capture.pcap
  pcapforge demo
"""

from __future__ import annotations

import asyncio
import json
import struct
import socket
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

app = typer.Typer(
    name="pcapforge",
    help="F-03 PCAPForge — network forensics investigator with AI analysis.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(Panel(
        "[bold red]PCAPForge[/bold red]  [bright_black]v0.1.0 — Network Forensics Investigator[/bright_black]\n"
        "[bright_black]F-03 — Forensic portfolio project | Flows + DNS + HTTP + TLS + AI narrative[/bright_black]",
        border_style="bright_black", padding=(0, 2),
    ))


def _print_summary(summary) -> None:
    s = summary.summary
    stats = summary.stats

    console.print(
        f"\n[bold]Analysis complete:[/bold]  "
        f"[red]{s['critical']} critical[/red]  "
        f"[dark_orange]{s['high']} high[/dark_orange]  "
        f"[yellow]{s['medium']} medium[/yellow]  "
        f"[bright_black]{s['total_findings']} total findings[/bright_black]  "
        f"({summary.duration_seconds:.2f}s)\n"
    )

    console.print(
        f"[bright_black]Packets: {stats.total_packets:,}  "
        f"Flows: {len(summary.flows)}  "
        f"DNS: {len(summary.dns_queries)}  "
        f"HTTP: {len(summary.http_requests)}  "
        f"Unique src IPs: {len(stats.unique_src_ips)}[/bright_black]\n"
    )

    findings = summary.sorted_findings()
    if findings:
        table = Table(title=f"Findings ({len(findings)} total)", show_header=True, header_style="bold")
        table.add_column("Sev", width=9)
        table.add_column("Category", width=16)
        table.add_column("Title", width=38)
        table.add_column("Description")

        for f in findings[:25]:
            c = f.severity.color
            table.add_row(
                f"[{c}]{f.severity.value.upper()}[/{c}]",
                f.category,
                f.title[:38],
                f.description[:65],
            )
        console.print(table)

    if summary.ai_narrative:
        console.print()
        console.print(Panel(
            summary.ai_narrative,
            title="[purple]AI Incident Narrative[/purple]",
            border_style="purple",
        ))
        if summary.ai_threat_actor:
            console.print(f"\n[bold]Threat Actor:[/bold] {summary.ai_threat_actor}")
        if summary.ai_kill_chain:
            console.print("\n[bold]Kill Chain:[/bold]")
            for i, step in enumerate(summary.ai_kill_chain, 1):
                console.print(f"  [cyan]{i}.[/cyan] {step}")
        if summary.ai_mitre:
            console.print(f"\n[bold]MITRE:[/bold] {', '.join(summary.ai_mitre)}")

    # IOCs
    all_iocs = list({ioc for f in findings for ioc in f.iocs})[:15]
    if all_iocs:
        console.print(f"\n[bold]IOCs ({len(all_iocs)}):[/bold]")
        for ioc in all_iocs:
            console.print(f"  [red]{ioc}[/red]")


@app.command()
def analyze(
    pcap_file: Path = typer.Argument(..., help="Path to .pcap or .pcapng file"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("html", "--format", "-f", help="html|pdf|json"),
) -> None:
    """Full forensic analysis of a PCAP file."""
    _banner()

    if not pcap_file.exists():
        console.print(f"[red]File not found: {pcap_file}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Analyzing: {pcap_file.name}[/cyan]\n")

    from pcapforge.core.analyzer import analyze_pcap
    summary = asyncio.run(analyze_pcap(pcap_file, use_ai=not no_ai))
    _print_summary(summary)

    if output:
        _save_output(summary, output, fmt)


@app.command()
def flows(
    pcap_file: Path = typer.Argument(..., help="PCAP file"),
    top: int = typer.Option(20, "--top", "-n"),
) -> None:
    """Show top network flows from a PCAP."""
    _banner()
    if not pcap_file.exists():
        console.print(f"[red]File not found: {pcap_file}[/red]")
        raise typer.Exit(1)

    from pcapforge.parsers.pcap_reader import PcapReader
    reader = PcapReader(pcap_file)
    stats, flow_list, _, _, _ = reader.read()

    sorted_flows = sorted(flow_list, key=lambda f: f.total_bytes, reverse=True)
    table = Table(title=f"Top {top} flows by bytes", show_header=True, header_style="bold")
    table.add_column("Src IP", width=15)
    table.add_column("Dst IP", width=15)
    table.add_column("Port", width=6)
    table.add_column("Proto", width=8)
    table.add_column("Packets", width=8)
    table.add_column("Bytes", width=10)
    table.add_column("Duration", width=9)

    for fl in sorted_flows[:top]:
        table.add_row(
            fl.src_ip, fl.dst_ip, str(fl.dst_port),
            fl.protocol.value, str(fl.packets),
            _fmt_bytes(fl.total_bytes), f"{fl.duration_seconds}s",
        )
    console.print(table)
    console.print(f"\n[bright_black]Total: {stats.total_packets:,} packets, {_fmt_bytes(stats.total_bytes)}[/bright_black]")


@app.command()
def dns(
    pcap_file: Path = typer.Argument(..., help="PCAP file"),
    suspicious_only: bool = typer.Option(False, "--suspicious"),
) -> None:
    """Show DNS queries from a PCAP."""
    _banner()
    if not pcap_file.exists():
        console.print(f"[red]File not found: {pcap_file}[/red]")
        raise typer.Exit(1)

    from pcapforge.parsers.pcap_reader import PcapReader
    from pcapforge.detectors.dns_detector import DnsDetector
    reader = PcapReader(pcap_file)
    _, _, dns_queries, _, _ = reader.read()

    DnsDetector().detect(dns_queries)  # marks suspicious

    queries = [q for q in dns_queries if q.is_suspicious] if suspicious_only else dns_queries
    table = Table(title=f"DNS Queries ({len(queries)})", show_header=True, header_style="bold")
    table.add_column("Src IP", width=15)
    table.add_column("Query", width=40)
    table.add_column("Type", width=6)
    table.add_column("Responses", width=20)
    table.add_column("Flag")

    for q in queries[:50]:
        flag = f"[dark_orange]{q.suspicion_reason}[/dark_orange]" if q.is_suspicious else ""
        table.add_row(
            q.src_ip, q.query_name[:40], q.query_type,
            ", ".join(q.response_ips[:3]), flag,
        )
    console.print(table)


@app.command()
def demo(
    no_ai: bool = typer.Option(False, "--no-ai"),
    output: Optional[Path] = typer.Option(Path("pcapforge-demo-report.html"), "--output", "-o"),
) -> None:
    """Analyze a synthetic PCAP with attack traffic patterns."""
    _banner()
    console.print("[cyan]Generating synthetic attack PCAP for demo...[/cyan]\n")

    import tempfile
    pcap_data = _build_synthetic_pcap()

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(pcap_data)
        pcap_path = Path(f.name)

    try:
        from pcapforge.core.analyzer import analyze_pcap
        summary = asyncio.run(analyze_pcap(pcap_path, use_ai=not no_ai))
        summary.pcap_path = Path("synthetic_attack_demo.pcap")
        _print_summary(summary)

        if output:
            _save_output(summary, output, "html")
    finally:
        pcap_path.unlink(missing_ok=True)


def _build_synthetic_pcap() -> bytes:
    """Build a minimal PCAP with attack traffic patterns for demo."""
    # PCAP global header
    global_hdr = struct.pack("<IHHiIII",
        0xA1B2C3D4,  # magic
        2, 4,         # major, minor version
        0,            # thiszone
        0,            # sigfigs
        65535,        # snaplen
        1,            # network: LINKTYPE_ETHERNET
    )

    packets = []
    base_ts = 1700000000.0  # fixed timestamp for reproducibility

    def eth_ip_tcp(src_ip, dst_ip, sport, dport, payload=b"", ts_offset=0.0, flags=0x002):
        """Build Ethernet + IPv4 + TCP packet."""
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        dst_mac = b"\x00\xAA\xBB\xCC\xDD\xEE"
        ether_type = b"\x08\x00"

        # TCP
        tcp_hdr = struct.pack(">HHIIBBHHH",
            sport, dport,
            1000, 2000,   # seq, ack
            0x50, flags,  # data offset=5, flags (SYN=0x02, ACK=0x10, PSH|ACK=0x18)
            65535, 0, 0,  # window, checksum, urgent
        )

        # IPv4
        total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack(">BBHHHBBH4s4s",
            0x45, 0,       # version+IHL, DSCP
            total_len,     # total len
            0,             # ID
            0x4000,        # flags=DF, frag offset=0
            64, 6,         # TTL, protocol (TCP)
            0,             # checksum
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )

        frame = src_mac + dst_mac + ether_type + ip_hdr + tcp_hdr + payload
        ts_sec = int(base_ts + ts_offset)
        ts_usec = int((base_ts + ts_offset - ts_sec) * 1_000_000)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        return pkt_hdr + frame

    def eth_ip_udp(src_ip, dst_ip, sport, dport, payload=b"", ts_offset=0.0):
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        dst_mac = b"\x00\xAA\xBB\xCC\xDD\xEE"
        ether_type = b"\x08\x00"
        udp_hdr = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
        total_len = 20 + 8 + len(payload)
        ip_hdr = struct.pack(">BBHHHBBH4s4s",
            0x45, 0, total_len, 0,
            0x4000, 64, 17, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )
        frame = src_mac + dst_mac + ether_type + ip_hdr + udp_hdr + payload
        ts_sec = int(base_ts + ts_offset)
        ts_usec = 0
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        return pkt_hdr + frame

    def make_dns_query(name: str, qtype: int = 1) -> bytes:
        """Minimal DNS query packet."""
        labels = name.encode().split(b".")
        qname = b""
        for label in labels:
            qname += bytes([len(label)]) + label
        qname += b"\x00"
        return struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)

    # 1. Port scan: 192.168.1.100 probes many ports on 10.0.0.5
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 3389, 8080, 8443, 4444, 5900, 6379, 27017, 3306, 1433, 5432,
                 6667, 8888, 9999, 31337, 1337]:
        packets.append(eth_ip_tcp("192.168.1.100", "10.0.0.5", 54321, port, ts_offset=0.1))

    # 2. DNS — DGA domains + suspicious TLDs
    dga_domains = [
        "xkqwjdnmsrtv.com", "plzmxwqrtbvc.net", "hgfjkqwxztvm.xyz",
        "qzxwvtbmnprs.top", "lkjhgfdsazxc.work", "mnbvcxzlkjhg.xyz",
    ]
    for i, domain in enumerate(dga_domains):
        packets.append(eth_ip_udp("192.168.1.50", "8.8.8.8", 5353, 53,
                                   make_dns_query(domain), ts_offset=1.0 + i * 0.5))

    # 3. C2 beaconing: 192.168.1.50 → 198.51.100.10:4444 every ~30s
    for i in range(8):
        http_beacon = (
            b"GET /beacon HTTP/1.1\r\n"
            b"Host: 198.51.100.10\r\n"
            b"User-Agent: meterpreter/6.3\r\n"
            b"Connection: keep-alive\r\n\r\n"
        )
        packets.append(eth_ip_tcp("192.168.1.50", "198.51.100.10", 49152, 4444,
                                   http_beacon, ts_offset=10.0 + i * 30.0, flags=0x018))

    # 4. SQL injection attempt
    sqli_payload = (
        b"GET /login?user=admin'+OR+1=1--&pass=x HTTP/1.1\r\n"
        b"Host: 10.0.0.20\r\n"
        b"User-Agent: sqlmap/1.7\r\n\r\n"
    )
    packets.append(eth_ip_tcp("203.0.113.5", "10.0.0.20", 54000, 80,
                               sqli_payload, ts_offset=300.0, flags=0x018))

    # 5. Lateral movement: 192.168.1.50 → multiple internal hosts on SMB/RDP
    for target_ip, target_port in [
        ("10.0.0.10", 445), ("10.0.0.11", 445), ("10.0.0.12", 3389),
        ("10.0.0.13", 3389), ("10.0.0.14", 445), ("10.0.0.15", 5985),
    ]:
        packets.append(eth_ip_tcp("192.168.1.50", target_ip, 49200, target_port,
                                   ts_offset=400.0, flags=0x002))

    # 6. Large outbound transfer (exfiltration): 192.168.1.200 → 198.51.100.99
    big_payload = b"X" * 1400
    for i in range(50):
        packets.append(eth_ip_tcp("192.168.1.200", "198.51.100.99", 50000, 443,
                                   big_payload, ts_offset=500.0 + i * 0.1, flags=0x018))

    # 7. RDP brute force from external
    for i in range(15):
        packets.append(eth_ip_tcp("203.0.113.99", "10.0.0.5", 54100 + i, 3389,
                                   ts_offset=600.0 + i * 2.0, flags=0x002))

    return global_hdr + b"".join(packets)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n //= 1024
    return f"{n}GB"


def _save_output(summary, output: Path, fmt: str) -> None:
    from pcapforge.report.generator import generate_html, generate_pdf
    if fmt == "json":
        output.with_suffix(".json").write_text(
            json.dumps(summary.to_dict(), indent=2, default=str), encoding="utf-8"
        )
        console.print(f"\n[green]JSON saved -> {output.with_suffix('.json')}[/green]")
    elif fmt == "pdf":
        out = generate_pdf(summary, output.with_suffix(".pdf"))
        console.print(f"\n[green]Report saved -> {out}[/green]")
    else:
        out = generate_html(summary, output.with_suffix(".html"))
        console.print(f"\n[green]Report saved -> {out}[/green]")


if __name__ == "__main__":
    app()
