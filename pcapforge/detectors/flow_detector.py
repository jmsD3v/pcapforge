"""Flow-level forensic detectors — port scans, lateral movement, beaconing, exfiltration."""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from pcapforge.types.network import ConnectionFlow, ForensicFinding, Protocol, Severity


# Ports associated with C2 / malware
_SUSPICIOUS_PORTS = {
    4444, 4445, 4446,          # Meterpreter defaults
    1337, 31337,               # hacker tradition
    6666, 6667, 6668, 6669,    # IRC (botnets)
    8888, 9999,                # common backdoors
    2222,                      # alternative SSH (often misused)
    3333,                      # common backdoor
    12345, 54321,              # known backdoor ports
    65535,                     # max port (suspicious)
}

_LATERAL_MOVEMENT_PORTS = {
    445,    # SMB (pass-the-hash, lateral movement)
    3389,   # RDP
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    135,    # RPC
    139,    # NetBIOS
    5900,   # VNC
    23,     # Telnet
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class FlowDetector:
    """Detect suspicious patterns in network flows."""

    def detect(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []

        findings.extend(self._detect_port_scan(flows))
        findings.extend(self._detect_c2_beaconing(flows))
        findings.extend(self._detect_lateral_movement(flows))
        findings.extend(self._detect_suspicious_ports(flows))
        findings.extend(self._detect_large_transfers(flows))
        findings.extend(self._detect_rdp_bruteforce(flows))

        return findings

    def _detect_port_scan(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        """Detect port scans: single src IP → many dst ports on same host."""
        # src_ip → {dst_ip: set of dst_ports}
        scan_map: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        for flow in flows:
            scan_map[flow.src_ip][flow.dst_ip].add(flow.dst_port)

        findings: list[ForensicFinding] = []
        for src_ip, targets in scan_map.items():
            for dst_ip, ports in targets.items():
                if len(ports) >= 20:
                    sev = Severity.CRITICAL if len(ports) >= 100 else Severity.HIGH
                    findings.append(ForensicFinding(
                        severity=sev,
                        category="recon",
                        title=f"Port Scan: {src_ip} -> {dst_ip}",
                        description=f"{src_ip} probed {len(ports)} ports on {dst_ip}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        evidence=[f"{len(ports)} unique destination ports", f"Sample: {sorted(ports)[:10]}"],
                        mitre_techniques=["T1046"],
                        tags=["port_scan", "recon"],
                        iocs=[src_ip],
                    ))
        return findings

    def _detect_c2_beaconing(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        """Detect beaconing: many periodic connections to same dst."""
        # src → dst → list of flows
        c2_map: dict[tuple, list[ConnectionFlow]] = defaultdict(list)
        for flow in flows:
            if not _is_private(flow.dst_ip):
                c2_map[(flow.src_ip, flow.dst_ip, flow.dst_port)].append(flow)

        findings: list[ForensicFinding] = []
        for (src, dst, port), flow_list in c2_map.items():
            if len(flow_list) >= 5:
                # Check for regular intervals (beaconing indicator)
                times = sorted(f.start_time for f in flow_list)
                if len(times) >= 3:
                    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                    avg_interval = sum(intervals) / len(intervals)
                    # Regularity: std dev < 20% of mean
                    if avg_interval > 0:
                        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                        cv = (variance**0.5) / avg_interval
                        if cv < 0.3 and avg_interval < 3600:
                            findings.append(ForensicFinding(
                                severity=Severity.HIGH,
                                category="c2",
                                title=f"C2 Beaconing: {src} -> {dst}:{port}",
                                description=(
                                    f"{src} made {len(flow_list)} periodic connections to {dst}:{port} "
                                    f"(avg interval {avg_interval:.0f}s, regularity CV={cv:.2f})"
                                ),
                                src_ip=src,
                                dst_ip=dst,
                                dst_port=port,
                                evidence=[
                                    f"{len(flow_list)} connections",
                                    f"Avg interval: {avg_interval:.0f}s",
                                    f"Coefficient of variation: {cv:.2f}",
                                ],
                                mitre_techniques=["T1071", "T1571"],
                                tags=["beaconing", "c2"],
                                iocs=[dst, f"{dst}:{port}"],
                            ))
        return findings

    def _detect_lateral_movement(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        """Detect lateral movement: internal → internal on admin ports."""
        # src → set of (dst, port) pairs on lateral movement ports
        lateral_map: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for flow in flows:
            if (_is_private(flow.src_ip) and _is_private(flow.dst_ip)
                    and flow.dst_port in _LATERAL_MOVEMENT_PORTS):
                lateral_map[flow.src_ip].append((flow.dst_ip, flow.dst_port))

        findings: list[ForensicFinding] = []
        for src_ip, targets in lateral_map.items():
            unique_hosts = len({t[0] for t in targets})
            if unique_hosts >= 3:
                ports_used = {t[1] for t in targets}
                findings.append(ForensicFinding(
                    severity=Severity.CRITICAL,
                    category="lateral_movement",
                    title=f"Lateral Movement: {src_ip} -> {unique_hosts} internal hosts",
                    description=(
                        f"{src_ip} connected to {unique_hosts} internal hosts on "
                        f"admin/lateral-movement ports: {ports_used}"
                    ),
                    src_ip=src_ip,
                    evidence=[
                        f"{unique_hosts} unique internal targets",
                        f"Ports: {ports_used}",
                        f"Total connections: {len(targets)}",
                    ],
                    mitre_techniques=["T1021", "T1021.002", "T1021.001"],
                    tags=["lateral_movement", "internal"],
                    iocs=[src_ip],
                ))
        return findings

    def _detect_suspicious_ports(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        """Flag flows to known malware/C2 ports."""
        findings: list[ForensicFinding] = []
        seen: set[tuple] = set()
        for flow in flows:
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            if flow.dst_port in _SUSPICIOUS_PORTS and key not in seen:
                seen.add(key)
                findings.append(ForensicFinding(
                    severity=Severity.HIGH,
                    category="c2",
                    title=f"Suspicious Port: {flow.dst_ip}:{flow.dst_port}",
                    description=f"{flow.src_ip} connected to {flow.dst_ip}:{flow.dst_port} (known malware port)",
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol.value,
                    evidence=[f"Port {flow.dst_port} is associated with backdoors/C2"],
                    mitre_techniques=["T1571"],
                    tags=["suspicious_port", "c2"],
                    iocs=[flow.dst_ip, f"{flow.dst_ip}:{flow.dst_port}"],
                ))
        return findings

    def _detect_large_transfers(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        """Detect large outbound data transfers (potential exfiltration)."""
        # Sum bytes by (src_ip, dst_ip) pair for external destinations
        exfil_map: dict[tuple, int] = defaultdict(int)
        for flow in flows:
            if _is_private(flow.src_ip) and not _is_private(flow.dst_ip):
                exfil_map[(flow.src_ip, flow.dst_ip)] += flow.bytes_sent

        findings: list[ForensicFinding] = []
        for (src, dst), total_bytes in exfil_map.items():
            if total_bytes > 50 * 1024 * 1024:  # > 50 MB
                sev = Severity.CRITICAL if total_bytes > 500 * 1024 * 1024 else Severity.HIGH
                findings.append(ForensicFinding(
                    severity=sev,
                    category="exfiltration",
                    title=f"Large Outbound Transfer: {src} -> {dst}",
                    description=f"{src} sent {total_bytes / (1024*1024):.1f} MB to external host {dst}",
                    src_ip=src,
                    dst_ip=dst,
                    evidence=[f"{total_bytes / (1024*1024):.1f} MB outbound"],
                    mitre_techniques=["T1048", "T1041"],
                    tags=["exfiltration", "large_transfer"],
                    iocs=[dst],
                ))
        return findings

    def _detect_rdp_bruteforce(self, flows: list[ConnectionFlow]) -> list[ForensicFinding]:
        """Detect RDP brute force: many connections to port 3389."""
        rdp_src: dict[str, int] = defaultdict(int)
        rdp_dst: dict[str, set[str]] = defaultdict(set)
        for flow in flows:
            if flow.dst_port == 3389:
                rdp_src[flow.src_ip] += 1
                rdp_dst[flow.dst_ip].add(flow.src_ip)

        findings: list[ForensicFinding] = []
        for src_ip, count in rdp_src.items():
            if count >= 10 and not _is_private(src_ip):
                findings.append(ForensicFinding(
                    severity=Severity.HIGH,
                    category="brute_force",
                    title=f"RDP Brute Force from {src_ip}",
                    description=f"External {src_ip} attempted {count} RDP connections",
                    src_ip=src_ip,
                    dst_port=3389,
                    evidence=[f"{count} RDP connection attempts"],
                    mitre_techniques=["T1110.001", "T1021.001"],
                    tags=["rdp", "brute_force"],
                    iocs=[src_ip],
                ))
        return findings
