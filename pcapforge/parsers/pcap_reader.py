"""
PCAP reader — uses dpkt for low-level parsing.
Builds connection flows, DNS queries, HTTP requests, TLS sessions.
"""

from __future__ import annotations

import socket
import struct
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from pcapforge.types.network import (
    ConnectionFlow,
    DnsQuery,
    HttpRequest,
    NetworkStats,
    Protocol,
    TlsInfo,
)

try:
    import dpkt
    DPKT_OK = True
except ImportError:
    DPKT_OK = False


# Well-known port → Protocol mapping
_PORT_PROTO: dict[int, Protocol] = {
    21: Protocol.FTP,
    22: Protocol.SSH,
    23: Protocol.OTHER,    # telnet
    25: Protocol.SMTP,
    53: Protocol.DNS,
    80: Protocol.HTTP,
    110: Protocol.OTHER,   # POP3
    143: Protocol.OTHER,   # IMAP
    443: Protocol.HTTPS,
    445: Protocol.SMB,
    3389: Protocol.RDP,
    8080: Protocol.HTTP,
    8443: Protocol.HTTPS,
}


def _ip_to_str(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        elif len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        pass
    return addr.hex()


class PcapReader:
    """Read a PCAP/PCAPNG file and extract flows, DNS, HTTP, TLS."""

    def __init__(self, path: Path):
        self._path = path

    def read(self) -> tuple[NetworkStats, list[ConnectionFlow], list[DnsQuery], list[HttpRequest], list[TlsInfo]]:
        if not DPKT_OK:
            raise ImportError("dpkt not installed: pip install dpkt")

        stats = NetworkStats()
        flows: dict[str, ConnectionFlow] = {}
        dns_queries: list[DnsQuery] = []
        http_requests: list[HttpRequest] = []
        tls_sessions: list[TlsInfo] = []
        ip_bytes: dict[str, int] = defaultdict(int)

        try:
            with open(self._path, "rb") as f:
                try:
                    pcap = dpkt.pcap.Reader(f)
                except Exception:
                    f.seek(0)
                    pcap = dpkt.pcapng.Reader(f)

                for ts, buf in pcap:
                    stats.total_packets += 1
                    stats.total_bytes += len(buf)

                    if stats.capture_start == 0:
                        stats.capture_start = ts
                    stats.capture_end = ts

                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue

                    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue

                    ip = eth.data
                    src_ip = _ip_to_str(ip.src)
                    dst_ip = _ip_to_str(ip.dst)

                    stats.unique_src_ips.add(src_ip)
                    stats.unique_dst_ips.add(dst_ip)
                    ip_bytes[src_ip] += len(buf)

                    # Protocol routing
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        proto = _PORT_PROTO.get(tcp.dport,
                                 _PORT_PROTO.get(tcp.sport, Protocol.TCP))
                        stats.unique_dst_ports.add(tcp.dport)
                        stats.protocol_counts["tcp"] = stats.protocol_counts.get("tcp", 0) + 1

                        flow = _get_or_create_flow(
                            flows, src_ip, dst_ip, tcp.sport, tcp.dport, proto, ts
                        )
                        flow.packets += 1
                        flow.bytes_sent += len(buf)
                        flow.end_time = ts
                        _collect_tcp_flags(flow, tcp)

                        # HTTP detection
                        if tcp.data and proto in (Protocol.HTTP, Protocol.HTTPS):
                            _try_parse_http(tcp, src_ip, dst_ip, ts, http_requests)

                        # TLS/SSL detection
                        if tcp.data and len(tcp.data) > 5:
                            tls = _try_parse_tls(tcp.data, src_ip, dst_ip, tcp.dport)
                            if tls:
                                tls_sessions.append(tls)

                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        stats.unique_dst_ports.add(udp.dport)
                        stats.protocol_counts["udp"] = stats.protocol_counts.get("udp", 0) + 1
                        proto = _PORT_PROTO.get(udp.dport,
                                 _PORT_PROTO.get(udp.sport, Protocol.UDP))

                        flow = _get_or_create_flow(
                            flows, src_ip, dst_ip, udp.sport, udp.dport, proto, ts
                        )
                        flow.packets += 1
                        flow.bytes_sent += len(buf)
                        flow.end_time = ts

                        # DNS
                        if udp.dport == 53 or udp.sport == 53:
                            stats.protocol_counts["dns"] = stats.protocol_counts.get("dns", 0) + 1
                            dns = _try_parse_dns(udp.data, src_ip, ts)
                            if dns:
                                dns_queries.append(dns)

                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        stats.protocol_counts["icmp"] = stats.protocol_counts.get("icmp", 0) + 1

        except Exception as exc:
            raise RuntimeError(f"PCAP parse error: {exc}") from exc

        # Top talkers
        stats.top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]

        return stats, list(flows.values()), dns_queries, http_requests, tls_sessions


def _get_or_create_flow(
    flows: dict,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    proto: Protocol,
    ts: float,
) -> ConnectionFlow:
    # Canonical key: lower IP first for bidirectional matching
    key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto.value}"
    rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto.value}"

    if key in flows:
        return flows[key]
    if rev_key in flows:
        return flows[rev_key]

    flow = ConnectionFlow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        start_time=ts,
    )
    flows[key] = flow
    return flow


def _collect_tcp_flags(flow: ConnectionFlow, tcp: "dpkt.tcp.TCP") -> None:
    if tcp.flags & dpkt.tcp.TH_SYN:
        flow.flags.add("SYN")
    if tcp.flags & dpkt.tcp.TH_RST:
        flow.flags.add("RST")
    if tcp.flags & dpkt.tcp.TH_FIN:
        flow.flags.add("FIN")
    if tcp.flags & dpkt.tcp.TH_ACK:
        flow.flags.add("ACK")
    if tcp.flags & dpkt.tcp.TH_PUSH:
        flow.flags.add("PSH")


def _try_parse_dns(data: bytes, src_ip: str, ts: float) -> DnsQuery | None:
    try:
        dns = dpkt.dns.DNS(data)
        if not dns.qd:
            return None
        q = dns.qd[0]
        query_name = q.name
        query_type = {
            dpkt.dns.DNS_A: "A",
            dpkt.dns.DNS_AAAA: "AAAA",
            dpkt.dns.DNS_MX: "MX",
            dpkt.dns.DNS_TXT: "TXT",
            dpkt.dns.DNS_PTR: "PTR",
            dpkt.dns.DNS_NS: "NS",
            dpkt.dns.DNS_CNAME: "CNAME",
            dpkt.dns.DNS_SOA: "SOA",
        }.get(q.type, str(q.type))

        response_ips: list[str] = []
        if dns.an:
            for rr in dns.an:
                if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
                    response_ips.append(_ip_to_str(rr.rdata))
                elif rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
                    response_ips.append(_ip_to_str(rr.rdata))

        return DnsQuery(
            timestamp=ts,
            src_ip=src_ip,
            query_name=query_name,
            query_type=query_type,
            response_ips=response_ips,
        )
    except Exception:
        return None


def _try_parse_http(
    tcp: "dpkt.tcp.TCP",
    src_ip: str, dst_ip: str,
    ts: float,
    requests: list[HttpRequest],
) -> None:
    try:
        if not tcp.data:
            return
        # Try request
        req = dpkt.http.Request(tcp.data)
        method = req.method
        path = req.uri
        host = req.headers.get("host", dst_ip)
        ua = req.headers.get("user-agent", "")
        requests.append(HttpRequest(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            method=method,
            host=host,
            path=path,
            user_agent=ua,
        ))
    except Exception:
        try:
            # Try response
            resp = dpkt.http.Response(tcp.data)
            if requests:
                last = requests[-1]
                last.status_code = int(resp.status)
                last.content_type = resp.headers.get("content-type", "")
                last.body_size = len(resp.body) if resp.body else 0
        except Exception:
            pass


def _try_parse_tls(data: bytes, src_ip: str, dst_ip: str, dst_port: int) -> TlsInfo | None:
    """Extract SNI from TLS ClientHello."""
    try:
        if data[0] != 0x16:  # ContentType: Handshake
            return None
        if data[5] != 0x01:  # HandshakeType: ClientHello
            return None

        version_byte = data[1:3]
        version_map = {
            b"\x03\x01": "TLS 1.0",
            b"\x03\x02": "TLS 1.1",
            b"\x03\x03": "TLS 1.2",
            b"\x03\x04": "TLS 1.3",
        }
        version = version_map.get(bytes(version_byte), f"TLS 0x{version_byte.hex()}")

        # Parse SNI extension from ClientHello
        sni = _extract_sni(data)
        return TlsInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            sni=sni,
            version=version,
        )
    except Exception:
        return None


def _extract_sni(data: bytes) -> str:
    """Extract SNI hostname from TLS ClientHello extension."""
    try:
        # Skip: record(5) + handshake_type(1) + length(3) + version(2) + random(32) + session_id_len(1)
        offset = 5 + 1 + 3 + 2 + 32
        if offset >= len(data):
            return ""

        session_id_len = data[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(data):
            return ""
        cipher_suites_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2 + cipher_suites_len

        if offset + 1 > len(data):
            return ""
        compression_len = data[offset]
        offset += 1 + compression_len

        if offset + 2 > len(data):
            return ""
        extensions_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        end = offset + extensions_len
        while offset + 4 <= end and offset + 4 <= len(data):
            ext_type = struct.unpack(">H", data[offset:offset+2])[0]
            ext_len = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                if offset + 5 <= len(data):
                    sni_list_len = struct.unpack(">H", data[offset:offset+2])[0]
                    name_type = data[offset+2]
                    name_len = struct.unpack(">H", data[offset+3:offset+5])[0]
                    if name_type == 0 and offset + 5 + name_len <= len(data):
                        return data[offset+5:offset+5+name_len].decode("ascii", errors="replace")
            offset += ext_len

    except Exception:
        pass
    return ""
