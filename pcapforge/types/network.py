"""PCAPForge data models — network flows, findings, analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "bold red",
            "high": "dark_orange",
            "medium": "yellow",
            "low": "cyan",
            "info": "bright_black",
        }[self.value]


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    SMB = "smb"
    RDP = "rdp"
    OTHER = "other"


@dataclass
class ConnectionFlow:
    """A bidirectional network flow."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    packets: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    flags: set[str] = field(default_factory=set)   # TCP flags seen
    payload_samples: list[bytes] = field(default_factory=list)

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol.value}"

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return round(self.end_time - self.start_time, 3)
        return 0.0

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "packets": self.packets,
            "bytes_total": self.total_bytes,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class DnsQuery:
    timestamp: float
    src_ip: str
    query_name: str
    query_type: str        # A, AAAA, MX, TXT, PTR, etc.
    response_ips: list[str] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class HttpRequest:
    timestamp: float
    src_ip: str
    dst_ip: str
    method: str
    host: str
    path: str
    user_agent: str = ""
    status_code: int = 0
    content_type: str = ""
    body_size: int = 0
    is_suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class TlsInfo:
    src_ip: str
    dst_ip: str
    dst_port: int
    sni: str = ""           # Server Name Indication
    version: str = ""       # TLS 1.0, 1.2, 1.3
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    is_self_signed: bool = False
    is_expired: bool = False


@dataclass
class ForensicFinding:
    severity: Severity
    category: str              # lateral_movement, c2, exfiltration, recon, etc.
    title: str
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    evidence: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "iocs": self.iocs,
        }


@dataclass
class NetworkStats:
    total_packets: int = 0
    total_bytes: int = 0
    unique_src_ips: set[str] = field(default_factory=set)
    unique_dst_ips: set[str] = field(default_factory=set)
    unique_dst_ports: set[int] = field(default_factory=set)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    top_talkers: list[tuple[str, int]] = field(default_factory=list)  # (ip, bytes)
    capture_start: float = 0.0
    capture_end: float = 0.0

    @property
    def duration_seconds(self) -> float:
        if self.capture_start and self.capture_end:
            return round(self.capture_end - self.capture_start, 3)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_src_ips": len(self.unique_src_ips),
            "unique_dst_ips": len(self.unique_dst_ips),
            "unique_dst_ports": len(self.unique_dst_ports),
            "protocol_counts": self.protocol_counts,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class PcapSummary:
    pcap_path: Path
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    stats: NetworkStats = field(default_factory=NetworkStats)
    flows: list[ConnectionFlow] = field(default_factory=list)
    dns_queries: list[DnsQuery] = field(default_factory=list)
    http_requests: list[HttpRequest] = field(default_factory=list)
    tls_sessions: list[TlsInfo] = field(default_factory=list)
    findings: list[ForensicFinding] = field(default_factory=list)
    ai_narrative: str = ""
    ai_threat_actor: str = ""
    ai_kill_chain: list[str] = field(default_factory=list)
    ai_mitre: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def summary(self) -> dict:
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        all_iocs = list({ioc for f in self.findings for ioc in f.iocs})
        return {
            "total_findings": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "total_flows": len(self.flows),
            "dns_queries": len(self.dns_queries),
            "http_requests": len(self.http_requests),
            "tls_sessions": len(self.tls_sessions),
            "unique_iocs": len(all_iocs),
        }

    def sorted_findings(self) -> list[ForensicFinding]:
        return sorted(self.findings, key=lambda f: f.severity.weight, reverse=True)

    def to_dict(self) -> dict:
        return {
            "pcap": str(self.pcap_path),
            "analyzed_at": self.analyzed_at.isoformat(),
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "flows": [fl.to_dict() for fl in self.flows[:100]],
            "dns_queries": [
                {"src": d.src_ip, "name": d.query_name, "type": d.query_type,
                 "responses": d.response_ips, "suspicious": d.is_suspicious}
                for d in self.dns_queries[:100]
            ],
            "ai_narrative": self.ai_narrative,
            "ai_threat_actor": self.ai_threat_actor,
            "ai_kill_chain": self.ai_kill_chain,
            "ai_mitre": self.ai_mitre,
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": self.summary,
        }
