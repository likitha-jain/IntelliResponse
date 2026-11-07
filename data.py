"""Data definitions, threat intelligence cache, and seeded incident history for IntelliResponse."""
from __future__ import annotations

CATEGORY_LABELS = {
    "brute_force": "Brute Force",
    "port_scan": "Port Scan",
    "dns_beacon": "DNS Beaconing",
    "unknown": "Unknown Activity",
}

VERDICT_LABELS = {
    "TRUE_POSITIVE": "True Positive (Confirmed Attack)",
    "FALSE_POSITIVE": "False Positive (Benign / Scanner)",
}

ACTION_TEXT = {
    "block_ip": "Block source IP on edge firewall",
    "enforce_mfa": "Enforce MFA for targeted user accounts",
    "rotate_credentials": "Force credential rotation for compromised accounts",
    "allowlist_scanner": "Allowlist source IP as authorized security scanner",
    "allowlist_domain": "Allowlist domain in DNS sinkhole & egress proxy",
    "isolate_host": "Isolate affected host from network segment",
    "block_domain": "Block malicious domain on DNS resolver and proxy",
    "reimage_host": "Reimage workstation to eradicate persistent malware",
    "review_firewall_rules": "Review and tighten edge firewall rules",
    "reset_user_password": "Reset user password and revoke active sessions",
}

DEFAULT_ACTIONS = {
    "brute_force": ["block_ip", "enforce_mfa", "rotate_credentials"],
    "port_scan": ["block_ip", "review_firewall_rules"],
    "dns_beacon": ["isolate_host", "block_domain", "reimage_host"],
    "unknown": ["review_firewall_rules"],
}

MITRE = {
    "brute_force": [
        ("T1110", "Brute Force"),
        ("T1110.001", "Password Guessing"),
        ("T1110.003", "Password Spraying"),
    ],
    "port_scan": [
        ("T1046", "Network Service Discovery"),
        ("T1595.001", "Port Scanning"),
    ],
    "dns_beacon": [
        ("T1071.004", "DNS Application Protocol"),
        ("T1568", "Dynamic Resolution"),
        ("T1053.005", "Scheduled Task Persistence"),
    ],
    "unknown": [
        ("T1000", "Unclassified Reconnaissance"),
    ],
}

ASSETS = {
    "ssh": {
        "host": "bastion-01.corp.internal",
        "product": "OpenSSH",
        "version": "8.9p1",
        "cves": ["CVE-2023-48795", "CVE-2024-6387"],
    },
    "network": {
        "host": "edge-fw-01.dmz.internal",
        "product": "PaloAlto PAN-OS",
        "version": "10.2.4",
        "cves": ["CVE-2024-3400"],
    },
    "rdp": {
        "host": "legacy-gw.corp.internal",
        "product": "Windows Server RDP Gateway",
        "version": "2019",
        "cves": ["CVE-2019-0708"],
    },
    "dns": {
        "host": "dc-dns-01.corp.internal",
        "product": "BIND DNS",
        "version": "9.18",
        "cves": ["CVE-2023-2828"],
    },
}

OSINT = {
    "ip": {
        "203.0.113.10": {"pulses": 14, "tags": ["botnet", "credential-stuffing", "ssh-brute"]},
        "203.0.113.77": {"pulses": 8, "tags": ["recon", "port-scan", "scanner"]},
        "203.0.113.99": {"pulses": 11, "tags": ["rdp-brute", "automated-recon"]},
        "203.0.113.150": {"pulses": 6, "tags": ["reconnaissance", "slow-scan"]},
        "192.0.2.44": {"pulses": 9, "tags": ["ssh-bruteforce", "wordlist-attack"]},
        "192.0.2.77": {"pulses": 7, "tags": ["password-spraying", "ssh"]},
        "192.0.2.101": {"pulses": 12, "tags": ["botnet", "ssh-bruteforce"]},
        "192.0.2.150": {"pulses": 10, "tags": ["botnet-node", "ssh-attack"]},
        "198.51.100.7": {"pulses": 0, "tags": ["qualys-scanner", "internal-audit"]},
        "203.0.113.200": {"pulses": 0, "tags": []},
    },
    "domain": {
        "c2-sync.example": {"pulses": 24, "tags": ["cobalt-strike", "c2", "beaconing", "apt"]},
        "vendor-telemetry.example": {"pulses": 0, "tags": ["benign-telemetry"]},
    },
    "cve": {
        "CVE-2024-6387": {"cvss": 8.1, "kev": True, "description": "regreSSHion: Remote unauthenticated code execution in OpenSSH"},
        "CVE-2023-48795": {"cvss": 5.9, "kev": False, "description": "Terrapin attack: SSH protocol prefix truncation"},
        "CVE-2024-3400": {"cvss": 10.0, "kev": True, "description": "Command injection vulnerability in PAN-OS GlobalProtect"},
        "CVE-2019-0708": {"cvss": 9.8, "kev": True, "description": "BlueKeep: Remote code execution in Remote Desktop Services"},
        "CVE-2023-2828": {"cvss": 7.5, "kev": False, "description": "BIND named DNS cache poisoning vulnerability"},
    },
}

SAMPLE_ALERTS = {
    "B - Recurring vulnerability scanner (198.51.100.7)": (
        "2026-11-06 01:15:00 firewall-alert: SYN sweep across ports 21, 22, 80, 443, 3389, 8080 on edge-fw-01.dmz.internal from 198.51.100.7\n"
        "2026-11-06 01:15:02 auth.log: Failed password for root from 198.51.100.7 port 51234 ssh2\n"
        "2026-11-06 01:15:04 auth.log: Failed password for admin from 198.51.100.7 port 51236 ssh2\n"
        "failures: 45 count: 1800 host=edge-fw-01.dmz.internal src=198.51.100.7 service=network category=port_scan"
    ),
    "A - New SSH brute force (from 192.0.2.180 in bad /24)": (
        "2026-11-05 23:42:10 auth.log: Failed password for invalid user admin from 192.0.2.180 port 44102 ssh2\n"
        "2026-11-05 23:42:14 auth.log: Failed password for invalid user root from 192.0.2.180 port 44104 ssh2\n"
        "2026-11-05 23:42:19 auth.log: Failed password for invalid user ubuntu from 192.0.2.180 port 44106 ssh2\n"
        "2026-11-05 23:42:24 auth.log: Failed password for invalid user test from 192.0.2.180 port 44108 ssh2\n"
        "failures: 285 count: 285 host=bastion-01.corp.internal src=192.0.2.180 service=ssh"
    ),
    "C - Recurring C2 beaconing (10.20.7.12 to c2-sync.example)": (
        "2026-11-06 01:30:12 named[1042]: client @0x7f88 10.20.7.12#53120: query: c2-sync.example IN TXT + (dc-dns-01.corp.internal)\n"
        "2026-11-06 01:31:12 named[1042]: client @0x7f88 10.20.7.12#53122: query: c2-sync.example IN TXT + (dc-dns-01.corp.internal)\n"
        "2026-11-06 01:32:12 named[1042]: client @0x7f88 10.20.7.12#53124: query: c2-sync.example IN TXT + (dc-dns-01.corp.internal)\n"
        "DNS TXT beaconing count=180 host=dc-dns-01.corp.internal src=10.20.7.12 service=dns category=dns_beacon qname=c2-sync.example"
    ),
}

_SEEDED_INCIDENTS = [
    {
        "id": "INC-001",
        "date": "2026-04-03",
        "category": "brute_force",
        "src": "203.0.113.10",
        "service": "ssh",
        "summary": "412 failed SSH logins in 9 min against root/admin",
        "cause": "Credential stuffing from botnet",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,enforce_mfa,rotate_credentials",
    },
    {
        "id": "INC-002",
        "date": "2026-04-09",
        "category": "port_scan",
        "src": "203.0.113.77",
        "service": "network",
        "summary": "SYN sweep across 1,800 ports on edge firewall",
        "cause": "Reconnaissance ahead of attack",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,review_firewall_rules",
    },
    {
        "id": "INC-003",
        "date": "2026-04-15",
        "category": "brute_force",
        "src": "198.51.100.7",
        "service": "ssh",
        "summary": "Burst of failed SSH logins from internal range",
        "cause": "Scheduled vulnerability scan by security team",
        "verdict": "FALSE_POSITIVE",
        "actions": "allowlist_scanner",
    },
    {
        "id": "INC-004",
        "date": "2026-04-22",
        "category": "brute_force",
        "src": "192.0.2.44",
        "service": "ssh",
        "summary": "230 failed SSH logins, usernames from common wordlist",
        "cause": "Password guessing campaign",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,enforce_mfa",
    },
    {
        "id": "INC-005",
        "date": "2026-04-29",
        "category": "dns_beacon",
        "src": "10.20.4.31",
        "service": "dns",
        "summary": "240 TXT queries at 60s interval to c2-sync.example",
        "cause": "Malware beaconing from workstation",
        "verdict": "TRUE_POSITIVE",
        "actions": "isolate_host,block_domain,reimage_host",
    },
    {
        "id": "INC-006",
        "date": "2026-05-06",
        "category": "brute_force",
        "src": "198.51.100.7",
        "service": "ssh",
        "summary": "Failed SSH logins from scanner range at 02:00",
        "cause": "Scheduled vulnerability scan",
        "verdict": "FALSE_POSITIVE",
        "actions": "allowlist_scanner",
    },
    {
        "id": "INC-007",
        "date": "2026-05-14",
        "category": "port_scan",
        "src": "198.51.100.7",
        "service": "network",
        "summary": "Port sweep of DMZ hosts",
        "cause": "Scheduled vulnerability scan",
        "verdict": "FALSE_POSITIVE",
        "actions": "allowlist_scanner",
    },
    {
        "id": "INC-008",
        "date": "2026-05-21",
        "category": "brute_force",
        "src": "192.0.2.101",
        "service": "ssh",
        "summary": "310 failed SSH logins in 12 min",
        "cause": "Password guessing campaign",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,rotate_credentials",
    },
    {
        "id": "INC-009",
        "date": "2026-05-30",
        "category": "brute_force",
        "src": "203.0.113.99",
        "service": "rdp",
        "summary": "180 failed RDP logins on legacy gateway",
        "cause": "Opportunistic RDP brute force",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,enforce_mfa",
    },
    {
        "id": "INC-010",
        "date": "2026-06-08",
        "category": "dns_beacon",
        "src": "10.20.7.12",
        "service": "dns",
        "summary": "Periodic DNS TXT lookups to c2-sync.example",
        "cause": "Malware beaconing",
        "verdict": "TRUE_POSITIVE",
        "actions": "isolate_host,block_domain",
    },
    {
        "id": "INC-011",
        "date": "2026-06-17",
        "category": "port_scan",
        "src": "203.0.113.150",
        "service": "network",
        "summary": "Slow scan of 22/3389/445 over 40 min",
        "cause": "Reconnaissance",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip",
    },
    {
        "id": "INC-012",
        "date": "2026-06-25",
        "category": "brute_force",
        "src": "198.51.100.7",
        "service": "ssh",
        "summary": "Failed SSH logins from scanner range",
        "cause": "Scheduled vulnerability scan",
        "verdict": "FALSE_POSITIVE",
        "actions": "allowlist_scanner",
    },
    {
        "id": "INC-013",
        "date": "2026-07-03",
        "category": "brute_force",
        "src": "203.0.113.10",
        "service": "ssh",
        "summary": "Repeat offender: 390 failed SSH logins",
        "cause": "Credential stuffing, same source as INC-001",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,enforce_mfa",
    },
    {
        "id": "INC-014",
        "date": "2026-07-12",
        "category": "dns_beacon",
        "src": "10.20.9.5",
        "service": "dns",
        "summary": "Regular DNS lookups to vendor telemetry domain",
        "cause": "Legacy monitoring agent polling",
        "verdict": "FALSE_POSITIVE",
        "actions": "allowlist_domain",
    },
    {
        "id": "INC-015",
        "date": "2026-07-22",
        "category": "brute_force",
        "src": "192.0.2.77",
        "service": "ssh",
        "summary": "275 failed SSH logins in 8 min",
        "cause": "Password guessing campaign",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,enforce_mfa,rotate_credentials",
    },
    {
        "id": "INC-016",
        "date": "2026-08-04",
        "category": "port_scan",
        "src": "203.0.113.77",
        "service": "network",
        "summary": "Repeat SYN sweep from known recon source",
        "cause": "Reconnaissance (same source as INC-002)",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip",
    },
    {
        "id": "INC-017",
        "date": "2026-08-19",
        "category": "brute_force",
        "src": "203.0.113.200",
        "service": "ssh",
        "summary": "12 failed SSH logins for one user then success",
        "cause": "Admin returned from leave and forgot password",
        "verdict": "FALSE_POSITIVE",
        "actions": "reset_user_password",
    },
    {
        "id": "INC-018",
        "date": "2026-09-02",
        "category": "dns_beacon",
        "src": "10.20.7.12",
        "service": "dns",
        "summary": "Beaconing resumed after reimage to c2-sync.example",
        "cause": "Persistence survived reimage (scheduled task)",
        "verdict": "TRUE_POSITIVE",
        "actions": "isolate_host,block_domain,reimage_host",
    },
    {
        "id": "INC-019",
        "date": "2026-09-15",
        "category": "brute_force",
        "src": "192.0.2.150",
        "service": "ssh",
        "summary": "340 failed SSH logins in 10 min",
        "cause": "Password guessing campaign",
        "verdict": "TRUE_POSITIVE",
        "actions": "block_ip,enforce_mfa",
    },
    {
        "id": "INC-020",
        "date": "2026-10-01",
        "category": "port_scan",
        "src": "198.51.100.7",
        "service": "network",
        "summary": "Port sweep of DMZ hosts",
        "cause": "Scheduled vulnerability scan",
        "verdict": "FALSE_POSITIVE",
        "actions": "allowlist_scanner",
    },
]


def incidents() -> list[dict]:
    """Return the 20 seeded incidents."""
    return [dict(inc) for inc in _SEEDED_INCIDENTS]
