"""PCAPForge main analysis pipeline."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from pcapforge.parsers.pcap_reader import PcapReader
from pcapforge.detectors.flow_detector import FlowDetector
from pcapforge.detectors.dns_detector import DnsDetector
from pcapforge.detectors.http_detector import HttpDetector
from pcapforge.types.network import PcapSummary


async def analyze_pcap(
    path: Path,
    use_ai: bool = True,
) -> PcapSummary:
    """
    Full PCAP analysis pipeline:
    1. Parse flows, DNS, HTTP, TLS from PCAP
    2. Detect port scans, lateral movement, beaconing, exfiltration
    3. Detect DNS anomalies (DGA, tunneling, fast-flux)
    4. Detect HTTP attacks (SQLi, XSS, scanners, C2 UAs)
    5. AI narrative (optional)
    """
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")

    start = time.perf_counter()
    summary = PcapSummary(pcap_path=path)

    # Step 1: Parse
    reader = PcapReader(path)
    stats, flows, dns_queries, http_requests, tls_sessions = reader.read()

    summary.stats = stats
    summary.flows = flows
    summary.dns_queries = dns_queries
    summary.http_requests = http_requests
    summary.tls_sessions = tls_sessions

    # Step 2-4: Detect
    all_findings = []
    all_findings.extend(FlowDetector().detect(flows))
    all_findings.extend(DnsDetector().detect(dns_queries))
    all_findings.extend(HttpDetector().detect(http_requests))

    summary.findings = all_findings

    # Step 5: AI
    if use_ai and (all_findings or flows):
        from pcapforge.core.ai_analyzer import analyze_network
        await analyze_network(summary)

    summary.duration_seconds = time.perf_counter() - start
    return summary


