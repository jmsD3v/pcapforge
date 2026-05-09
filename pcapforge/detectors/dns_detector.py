"""DNS forensic detector — DGA, tunneling, fast-flux, suspicious TLDs."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

from pcapforge.types.network import DnsQuery, ForensicFinding, Severity


# Suspicious TLDs often used for malware/C2
_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",    # free TLDs abused heavily
    ".pw", ".top", ".xyz", ".click",
    ".work", ".men", ".win", ".review",
    ".loan", ".science", ".racing", ".party",
    ".download", ".accountants",
}

# DNS over non-standard ports is already caught by flow detector
# TXT record types often used for C2 / DNS tunneling
_TUNNEL_INDICATORS = re.compile(
    r"[a-zA-Z0-9+/]{30,}|"   # base64-like
    r"(?:[0-9a-fA-F]{2}){16,}",   # hex-encoded
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values() if c > 0)


def _is_dga_domain(domain: str) -> tuple[bool, str]:
    """Heuristic DGA detection on the subdomain/hostname part."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False, ""

    # Check registrable domain (second-to-last + last)
    label = parts[-2]  # e.g., "xkqwjdnm" in "xkqwjdnm.com"

    if len(label) < 6:
        return False, ""

    entropy = _shannon_entropy(label)
    consonant_ratio = sum(1 for c in label.lower() if c in "bcdfghjklmnpqrstvwxyz") / len(label)
    digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)
    has_vowels = any(c in "aeiou" for c in label.lower())

    # DGA signals: high entropy, high consonant ratio, no vowels, mixed digits
    score = 0
    if entropy > 3.5:
        score += 2
    if consonant_ratio > 0.7:
        score += 2
    if not has_vowels:
        score += 2
    if digit_ratio > 0.3:
        score += 1
    if len(label) > 12:
        score += 1

    if score >= 5:
        return True, f"entropy={entropy:.2f}, consonant_ratio={consonant_ratio:.2f}"
    return False, ""


class DnsDetector:
    """Detect DNS-based attack patterns."""

    def detect(self, queries: list[DnsQuery]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []

        # Mark suspicious queries in place
        for q in queries:
            is_dga, reason = _is_dga_domain(q.query_name)
            if is_dga:
                q.is_suspicious = True
                q.suspicion_reason = f"DGA: {reason}"
            for tld in _SUSPICIOUS_TLDS:
                if q.query_name.endswith(tld):
                    q.is_suspicious = True
                    q.suspicion_reason = f"Suspicious TLD: {tld}"

        findings.extend(self._detect_dga_activity(queries))
        findings.extend(self._detect_dns_tunneling(queries))
        findings.extend(self._detect_fast_flux(queries))
        findings.extend(self._detect_nxdomain_storm(queries))
        findings.extend(self._detect_suspicious_tlds(queries))

        return findings

    def _detect_dga_activity(self, queries: list[DnsQuery]) -> list[ForensicFinding]:
        dga_per_src: dict[str, list[DnsQuery]] = defaultdict(list)
        for q in queries:
            is_dga, reason = _is_dga_domain(q.query_name)
            if is_dga:
                dga_per_src[q.src_ip].append(q)

        findings: list[ForensicFinding] = []
        for src_ip, dga_queries in dga_per_src.items():
            if len(dga_queries) >= 3:
                samples = [q.query_name for q in dga_queries[:5]]
                findings.append(ForensicFinding(
                    severity=Severity.HIGH,
                    category="c2",
                    title=f"DGA Activity from {src_ip}",
                    description=f"{src_ip} queried {len(dga_queries)} algorithmically-generated domains",
                    src_ip=src_ip,
                    evidence=[f"{len(dga_queries)} DGA-like domains", f"Samples: {samples}"],
                    mitre_techniques=["T1568.002"],
                    tags=["dga", "c2"],
                    iocs=samples,
                ))
        return findings

    def _detect_dns_tunneling(self, queries: list[DnsQuery]) -> list[ForensicFinding]:
        """Detect DNS tunneling: TXT queries with encoded data, long subdomains."""
        findings: list[ForensicFinding] = []
        tunnel_candidates: dict[str, list[DnsQuery]] = defaultdict(list)

        for q in queries:
            suspicious = False
            reason = ""

            # TXT queries with suspicious data
            if q.query_type == "TXT" and q.response_ips:
                for resp in q.response_ips:
                    if _TUNNEL_INDICATORS.search(resp):
                        suspicious = True
                        reason = "TXT record with encoded data"

            # Extremely long DNS labels (> 50 chars) = tunneling
            labels = q.query_name.split(".")
            max_label_len = max(len(l) for l in labels) if labels else 0
            if max_label_len > 50:
                suspicious = True
                reason = f"Extremely long DNS label ({max_label_len} chars)"

            # Many subdomain levels (> 5) = tunneling
            if len(labels) > 6:
                suspicious = True
                reason = f"Deep subdomain nesting ({len(labels)} levels)"

            if suspicious:
                # Get root domain (last 2 parts)
                root = ".".join(q.query_name.rstrip(".").split(".")[-2:])
                tunnel_candidates[root].append(q)

        for root, qs in tunnel_candidates.items():
            if len(qs) >= 2:
                findings.append(ForensicFinding(
                    severity=Severity.CRITICAL,
                    category="exfiltration",
                    title=f"DNS Tunneling to {root}",
                    description=f"{len(qs)} suspicious DNS queries to {root} suggest DNS tunneling",
                    evidence=[q.query_name for q in qs[:5]],
                    mitre_techniques=["T1071.004", "T1048.003"],
                    tags=["dns_tunneling", "exfiltration"],
                    iocs=[root] + [q.query_name for q in qs[:3]],
                ))
        return findings

    def _detect_fast_flux(self, queries: list[DnsQuery]) -> list[ForensicFinding]:
        """Detect fast-flux: same domain resolves to many different IPs."""
        domain_ips: dict[str, set[str]] = defaultdict(set)
        for q in queries:
            for ip in q.response_ips:
                domain_ips[q.query_name].add(ip)

        findings: list[ForensicFinding] = []
        for domain, ips in domain_ips.items():
            if len(ips) >= 5:
                findings.append(ForensicFinding(
                    severity=Severity.HIGH,
                    category="c2",
                    title=f"Fast-Flux DNS: {domain}",
                    description=f"{domain} resolved to {len(ips)} different IP addresses (fast-flux)",
                    evidence=[f"{len(ips)} unique IPs", f"IPs: {list(ips)[:8]}"],
                    mitre_techniques=["T1568.001"],
                    tags=["fast_flux", "c2"],
                    iocs=[domain] + list(ips)[:5],
                ))
        return findings

    def _detect_nxdomain_storm(self, queries: list[DnsQuery]) -> list[ForensicFinding]:
        """Detect DGA iteration: many NXDOMAIN (no response IPs)."""
        nxdomain_src: dict[str, int] = defaultdict(int)
        for q in queries:
            if not q.response_ips and q.query_type == "A":
                nxdomain_src[q.src_ip] += 1

        findings: list[ForensicFinding] = []
        for src_ip, count in nxdomain_src.items():
            if count >= 20:
                findings.append(ForensicFinding(
                    severity=Severity.HIGH,
                    category="c2",
                    title=f"NXDOMAIN Storm from {src_ip}",
                    description=f"{src_ip} received {count} NXDOMAIN responses — DGA iteration likely",
                    src_ip=src_ip,
                    evidence=[f"{count} NXDOMAIN responses"],
                    mitre_techniques=["T1568.002"],
                    tags=["nxdomain", "dga", "c2"],
                    iocs=[src_ip],
                ))
        return findings

    def _detect_suspicious_tlds(self, queries: list[DnsQuery]) -> list[ForensicFinding]:
        """Group queries to suspicious TLDs."""
        tld_queries: dict[str, list[str]] = defaultdict(list)
        for q in queries:
            for tld in _SUSPICIOUS_TLDS:
                if q.query_name.endswith(tld):
                    tld_queries[tld].append(q.query_name)

        findings: list[ForensicFinding] = []
        for tld, domains in tld_queries.items():
            unique = list(dict.fromkeys(domains))
            if len(unique) >= 3:
                findings.append(ForensicFinding(
                    severity=Severity.MEDIUM,
                    category="recon",
                    title=f"Suspicious TLD Queries: {tld}",
                    description=f"{len(unique)} unique domains queried under TLD {tld}",
                    evidence=[f"Domains: {unique[:5]}"],
                    mitre_techniques=["T1071.004"],
                    tags=["suspicious_tld"],
                    iocs=unique[:5],
                ))
        return findings
