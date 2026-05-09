"""HTTP forensic detector — webshell requests, SQLi, XSS, user-agent anomalies."""

from __future__ import annotations

import re
from collections import defaultdict

from pcapforge.types.network import ForensicFinding, HttpRequest, Severity


_RE_SQLI = re.compile(
    r"(?:union\s+select|select\s+.*from|insert\s+into|update\s+.*set|delete\s+from|"
    r"drop\s+table|exec\s*\(|xp_cmdshell|information_schema|sleep\s*\(|benchmark\s*\(|"
    r"or\s+1=1|and\s+1=1|'\s*or\s*'|--\s*$|;\s*--)",
    re.IGNORECASE,
)

_RE_XSS = re.compile(
    r"(?:<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|"
    r"eval\s*\(|src\s*=\s*(?:javascript|data)|<iframe|<img[^>]+src)",
    re.IGNORECASE,
)

_RE_PATH_TRAVERSAL = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%252e%252e%252f|"
    r"/etc/passwd|/etc/shadow|/proc/self|/windows/system32|boot\.ini)",
    re.IGNORECASE,
)

_RE_WEBSHELL = re.compile(
    r"(?:cmd=|exec=|command=|shell=|c99|r57|b374k|"
    r"passthru|system\(|shell_exec\(|popen\(|eval\(base64_decode|"
    r"phpinfo\(\)|\.php\?(?:cmd|exec|shell|c)=)",
    re.IGNORECASE,
)

_RE_SCANNER_UA = re.compile(
    r"(?:nikto|nessus|masscan|nmap|zap|burpsuite|sqlmap|dirbuster|gobuster|"
    r"wfuzz|hydra|medusa|metasploit|python-requests/|curl/\d|wget/\d|"
    r"nuclei|testssl|whatweb|wpscan)",
    re.IGNORECASE,
)

_RE_C2_UA = re.compile(
    r"(?:meterpreter|msf|cobalt.?strike|empire|havoc|sliver|"
    r"Go-http-client/|python-urllib|java/\d|libwww-perl)",
    re.IGNORECASE,
)

_SENSITIVE_PATHS = [
    "/.env", "/.git/", "/config.php", "/wp-config.php",
    "/web.config", "/appsettings.json", "/database.yml",
    "/etc/passwd", "/etc/shadow", "/proc/self/environ",
    "/admin/", "/administrator/", "/phpmyadmin/",
    "/xmlrpc.php", "/wp-login.php",
]


class HttpDetector:
    """Detect suspicious HTTP patterns."""

    def detect(self, requests: list[HttpRequest]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []

        # Mark suspicious requests
        for req in requests:
            full_url = (req.path or "")
            if _RE_SQLI.search(full_url):
                req.is_suspicious = True
                req.suspicion_reason = "SQLi"
            elif _RE_XSS.search(full_url):
                req.is_suspicious = True
                req.suspicion_reason = "XSS"
            elif _RE_PATH_TRAVERSAL.search(full_url):
                req.is_suspicious = True
                req.suspicion_reason = "path_traversal"
            elif _RE_WEBSHELL.search(full_url):
                req.is_suspicious = True
                req.suspicion_reason = "webshell"

        findings.extend(self._detect_web_attacks(requests))
        findings.extend(self._detect_scanner_ua(requests))
        findings.extend(self._detect_c2_ua(requests))
        findings.extend(self._detect_sensitive_paths(requests))
        findings.extend(self._detect_http_bruteforce(requests))

        return findings

    def _detect_web_attacks(self, requests: list[HttpRequest]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []
        attack_by_src: dict[str, list[tuple[str, str]]] = defaultdict(list)

        for req in requests:
            if not req.is_suspicious:
                continue
            attack_by_src[req.src_ip].append((req.path, req.suspicion_reason))

        for src_ip, attacks in attack_by_src.items():
            by_type: dict[str, list[str]] = defaultdict(list)
            for path, reason in attacks:
                by_type[reason].append(path)

            for attack_type, paths in by_type.items():
                sev = Severity.CRITICAL if attack_type in ("SQLi", "webshell") else Severity.HIGH
                mitre = {
                    "SQLi": ["T1190", "T1059.007"],
                    "XSS": ["T1059.007"],
                    "path_traversal": ["T1083", "T1222"],
                    "webshell": ["T1505.003"],
                }.get(attack_type, ["T1190"])

                findings.append(ForensicFinding(
                    severity=sev,
                    category="web_attack",
                    title=f"{attack_type} Attack from {src_ip}",
                    description=f"{src_ip} sent {len(paths)} {attack_type} payloads",
                    src_ip=src_ip,
                    evidence=[f"{len(paths)} payloads"] + [p[:100] for p in paths[:3]],
                    mitre_techniques=mitre,
                    tags=[attack_type.lower(), "web_attack"],
                    iocs=[src_ip],
                ))
        return findings

    def _detect_scanner_ua(self, requests: list[HttpRequest]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []
        scanner_ips: dict[str, set[str]] = defaultdict(set)
        for req in requests:
            if req.user_agent and _RE_SCANNER_UA.search(req.user_agent):
                scanner_ips[req.src_ip].add(req.user_agent)

        for src_ip, uas in scanner_ips.items():
            findings.append(ForensicFinding(
                severity=Severity.HIGH,
                category="recon",
                title=f"Security Scanner: {src_ip}",
                description=f"{src_ip} used known security scanner User-Agent(s): {list(uas)[:3]}",
                src_ip=src_ip,
                evidence=list(uas)[:5],
                mitre_techniques=["T1595", "T1046"],
                tags=["scanner", "recon"],
                iocs=[src_ip],
            ))
        return findings

    def _detect_c2_ua(self, requests: list[HttpRequest]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []
        seen: set[str] = set()
        for req in requests:
            if req.user_agent and _RE_C2_UA.search(req.user_agent):
                key = f"{req.src_ip}:{req.user_agent[:50]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(ForensicFinding(
                        severity=Severity.CRITICAL,
                        category="c2",
                        title=f"C2 Framework UA: {req.src_ip}",
                        description=f"C2/malware User-Agent detected: {req.user_agent[:120]}",
                        src_ip=req.src_ip,
                        dst_ip=req.dst_ip,
                        evidence=[f"UA: {req.user_agent}", f"URL: {req.host}{req.path[:80]}"],
                        mitre_techniques=["T1071.001"],
                        tags=["c2", "malware_ua"],
                        iocs=[req.src_ip, req.dst_ip],
                    ))
        return findings

    def _detect_sensitive_paths(self, requests: list[HttpRequest]) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []
        seen: set[str] = set()
        for req in requests:
            for sensitive in _SENSITIVE_PATHS:
                if sensitive.lower() in (req.path or "").lower():
                    key = f"{req.src_ip}:{sensitive}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(ForensicFinding(
                            severity=Severity.HIGH,
                            category="recon",
                            title=f"Sensitive Path Access: {sensitive}",
                            description=f"{req.src_ip} requested sensitive path: {req.host}{req.path[:100]}",
                            src_ip=req.src_ip,
                            dst_ip=req.dst_ip,
                            evidence=[f"{req.method} {req.host}{req.path[:100]}"],
                            mitre_techniques=["T1083"],
                            tags=["sensitive_path", "recon"],
                            iocs=[req.src_ip],
                        ))
                    break
        return findings

    def _detect_http_bruteforce(self, requests: list[HttpRequest]) -> list[ForensicFinding]:
        """Detect HTTP login brute force: many POSTs to same login endpoint."""
        post_map: dict[tuple, int] = defaultdict(int)
        for req in requests:
            if req.method == "POST":
                path_lower = (req.path or "").lower()
                if any(kw in path_lower for kw in ["login", "signin", "auth", "wp-login", "xmlrpc"]):
                    post_map[(req.src_ip, req.host, req.path)] += 1

        findings: list[ForensicFinding] = []
        for (src, host, path), count in post_map.items():
            if count >= 10:
                findings.append(ForensicFinding(
                    severity=Severity.HIGH,
                    category="brute_force",
                    title=f"HTTP Brute Force: {src} -> {host}",
                    description=f"{src} made {count} POST requests to {host}{path} (login brute force)",
                    src_ip=src,
                    evidence=[f"{count} POST requests", f"Target: {host}{path}"],
                    mitre_techniques=["T1110.001"],
                    tags=["brute_force", "http"],
                    iocs=[src],
                ))
        return findings
