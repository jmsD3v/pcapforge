"""Gemini AI narrative for network forensics analysis."""

from __future__ import annotations

import asyncio
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pcapforge.types.network import PcapSummary


async def _call_gemini(prompt: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return ""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: model.generate_content(prompt))
        return response.text.strip()
    except Exception:
        return ""


async def analyze_network(summary: "PcapSummary") -> None:
    """Generate AI incident narrative from network forensics data."""
    stats = summary.stats
    findings = summary.sorted_findings()
    if not findings:
        return

    critical = [f for f in findings if f.severity.value == "critical"]
    high = [f for f in findings if f.severity.value == "high"]

    # Build context
    finding_lines = []
    for f in findings[:20]:
        line = f"[{f.severity.value.upper()}] [{f.category}] {f.title}: {f.description[:120]}"
        if f.mitre_techniques:
            line += f" | MITRE: {', '.join(f.mitre_techniques[:3])}"
        finding_lines.append(line)

    all_iocs = list({ioc for f in findings for ioc in f.iocs})[:20]
    all_mitre = list({t for f in findings for t in f.mitre_techniques})[:15]

    # Top DNS queries
    suspicious_dns = [q.query_name for q in summary.dns_queries if q.is_suspicious][:10]
    # External connections
    external_conns = [
        f"{fl.src_ip} -> {fl.dst_ip}:{fl.dst_port}"
        for fl in summary.flows
        if not _is_private(fl.dst_ip)
    ][:10]

    prompt = f"""You are a senior network forensics analyst at a CERT/SOC. Analyze this PCAP investigation.

Capture statistics:
- Duration: {stats.duration_seconds:.0f}s
- Packets: {stats.total_packets:,}
- Bytes: {stats.total_bytes:,}
- Unique source IPs: {len(stats.unique_src_ips)}
- Unique destination ports: {len(stats.unique_dst_ports)}

Forensic findings ({len(findings)} total, {len(critical)} critical, {len(high)} high):
{chr(10).join(f'  {line}' for line in finding_lines)}

Suspicious DNS queries: {', '.join(suspicious_dns) or 'none'}
External connections: {', '.join(external_conns) or 'none'}
MITRE techniques observed: {', '.join(all_mitre)}
IOCs: {', '.join(all_iocs[:15]) or 'none'}

Provide:
1. NARRATIVE: 3-4 sentence attack timeline reconstruction — what the attacker did, what phase of the kill chain, what the goal appears to be
2. THREAT_ACTOR: Likely threat actor type (APT/ransomware/opportunistic/insider/red team)
3. KILL_CHAIN:
- <phase 1>
- <phase 2>
- <phase 3>
4. MITRE_TECHNIQUES: <T1234, T1456, ...>

Format EXACTLY:
NARRATIVE: <narrative>
THREAT_ACTOR: <actor type and one-sentence rationale>
KILL_CHAIN:
- <phase>
- <phase>
MITRE_TECHNIQUES: <techniques>"""

    response = await _call_gemini(prompt)
    if not response:
        return

    narrative = ""
    threat_actor = ""
    kill_chain: list[str] = []
    mitre: list[str] = []
    in_kill_chain = False

    for line in response.splitlines():
        line = line.strip()
        if line.startswith("NARRATIVE:"):
            narrative = line[10:].strip()
            in_kill_chain = False
        elif line.startswith("THREAT_ACTOR:"):
            threat_actor = line[13:].strip()
            in_kill_chain = False
        elif line.startswith("KILL_CHAIN:"):
            in_kill_chain = True
        elif line.startswith("MITRE_TECHNIQUES:"):
            in_kill_chain = False
            mitre = re.findall(r"T\d{4}(?:\.\d{3})?", line)
        elif in_kill_chain and line.startswith("- "):
            kill_chain.append(line[2:].strip())
        elif narrative and not in_kill_chain and line and not any(
            line.startswith(p) for p in ["NARRATIVE", "THREAT", "KILL", "MITRE"]
        ):
            narrative += " " + line

    if narrative:
        summary.ai_narrative = narrative
    if threat_actor:
        summary.ai_threat_actor = threat_actor
    if kill_chain:
        summary.ai_kill_chain = kill_chain[:6]
    if mitre:
        summary.ai_mitre = mitre


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False
