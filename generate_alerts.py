import json
import random
from datetime import datetime, timedelta

# Types d'alertes réalistes Wazuh
ALERTES = [
    {
        "rule_description": "Multiple authentication failures",
        "rule_level": 10,
        "rule_groups": ["authentication_failed", "syslog"],
        "category": "Brute Force",
        "is_real_threat": True
    },
    {
        "rule_description": "SQL injection attempt detected",
        "rule_level": 12,
        "rule_groups": ["web", "attack"],
        "category": "Web Attack",
        "is_real_threat": True
    },
    {
        "rule_description": "Port scan detected from external IP",
        "rule_level": 8,
        "rule_groups": ["network", "scan"],
        "category": "Reconnaissance",
        "is_real_threat": True
    },
    {
        "rule_description": "Rootkit detection - suspicious file modified",
        "rule_level": 14,
        "rule_groups": ["rootcheck"],
        "category": "Malware",
        "is_real_threat": True
    },
    {
        "rule_description": "Suspicious process execution",
        "rule_level": 11,
        "rule_groups": ["process", "attack"],
        "category": "Execution",
        "is_real_threat": True
    },
    {
        "rule_description": "SSH login success",
        "rule_level": 3,
        "rule_groups": ["authentication_success", "syslog"],
        "category": "Normal Activity",
        "is_real_threat": False  # faux positif
    },
    {
        "rule_description": "System audit event",
        "rule_level": 2,
        "rule_groups": ["audit"],
        "category": "Normal Activity",
        "is_real_threat": False  # faux positif
    },
    {
        "rule_description": "Windows update service started",
        "rule_level": 3,
        "rule_groups": ["windows", "system"],
        "category": "Normal Activity",
        "is_real_threat": False  # faux positif
    },
    {
        "rule_description": "Unauthorized file access attempt",
        "rule_level": 9,
        "rule_groups": ["file_access", "audit"],
        "category": "Privilege Escalation",
        "is_real_threat": True
    },
    {
        "rule_description": "Firewall rule violation",
        "rule_level": 7,
        "rule_groups": ["firewall", "network"],
        "category": "Policy Violation",
        "is_real_threat": True
    },
    {
        "rule_description": "Antivirus scan completed successfully",
        "rule_level": 1,
        "rule_groups": ["antivirus"],
        "category": "Normal Activity",
        "is_real_threat": False  # faux positif
    },
    {
        "rule_description": "XSS attack attempt on web application",
        "rule_level": 11,
        "rule_groups": ["web", "attack"],
        "category": "Web Attack",
        "is_real_threat": True
    },
]

AGENTS = [
    "server-prod-01", "server-prod-02",
    "dc-01", "web-server-01",
    "workstation-15", "workstation-22",
    "firewall-01", "db-server-01"
]

def generer_ip():
    return f"192.168.{random.randint(1,5)}.{random.randint(1,254)}"

def generer_ip_externe():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def generer_alerte(index):
    template = random.choice(ALERTES)
    now = datetime.now() - timedelta(minutes=random.randint(0, 1440))
    
    return {
        "id": f"ALT-{index:04d}",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "rule": {
            "description": template["rule_description"],
            "level": template["rule_level"],
            "groups": template["rule_groups"],
            "category": template["category"]
        },
        "agent": {
            "name": random.choice(AGENTS),
            "ip": generer_ip()
        },
        "data": {
            "srcip": generer_ip_externe() if template["is_real_threat"] else generer_ip(),
            "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS", "SSH"])
        },
        "is_real_threat": template["is_real_threat"]  # pour évaluer l'IA après
    }

# Génère 50 alertes
alertes = [generer_alerte(i) for i in range(1, 51)]

with open("data/alertes_wazuh.json", "w", encoding="utf-8") as f:
    json.dump(alertes, f, indent=2, ensure_ascii=False)

print(f" {len(alertes)} alertes générées dans data/alertes_wazuh.json")
print(f"   Vraies menaces : {sum(1 for a in alertes if a['is_real_threat'])}")
print(f"   Faux positifs  : {sum(1 for a in alertes if not a['is_real_threat'])}")