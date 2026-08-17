# backend/simulator/attack_scenarios.py
"""
Three canned APT attack scenarios for demo.
Each scenario is a list of LogEvent dicts that feed /ingest/logs.
"""
from datetime import datetime, timedelta
import uuid

BASE_TIME = datetime(2026, 8, 21, 9, 0, 0)


def ts(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat() + "Z"


# ── Scenario 1: Spear-Phishing → Code Execution → Exfiltration ─────────────
SCENARIO_APT_PHISHING = [
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(0),
        "host":       "workstation-1",
        "pid":        1001,
        "ppid":       800,
        "process":    "winword.exe",
        "parent":     "explorer.exe",
        "event_type": "SPAWN",
        "target":     "cmd.exe",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(5),
        "host":       "workstation-1",
        "pid":        1002,
        "ppid":       1001,
        "process":    "cmd.exe",
        "parent":     "winword.exe",
        "event_type": "WRITE",
        "target":     "C:\\Users\\Public\\payload.ps1",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(10),
        "host":       "workstation-1",
        "pid":        1003,
        "ppid":       1002,
        "process":    "powershell.exe",
        "parent":     "cmd.exe",
        "event_type": "READ",
        "target":     "C:\\Users\\Public\\payload.ps1",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(15),
        "host":       "workstation-1",
        "pid":        1003,
        "ppid":       1002,
        "process":    "powershell.exe",
        "parent":     "cmd.exe",
        "event_type": "CONNECT",
        "target":     "185.220.101.47:443",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(30),
        "host":       "workstation-1",
        "pid":        1003,
        "ppid":       1002,
        "process":    "powershell.exe",
        "parent":     "cmd.exe",
        "event_type": "READ",
        "target":     "C:\\Users\\standard_user\\Documents\\financial_report.xlsx",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(35),
        "host":       "workstation-1",
        "pid":        1003,
        "ppid":       1002,
        "process":    "powershell.exe",
        "parent":     "cmd.exe",
        "event_type": "CONNECT",
        "target":     "185.220.101.47:8080",
        "user":       "standard_user",
    },
]


# ── Scenario 2: Credential Brute-Force → Lateral Movement ─────────────────
SCENARIO_LATERAL_MOVEMENT = [
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(0),
        "host":       "auth-server",
        "pid":        2001,
        "ppid":       1,
        "process":    "sshd",
        "parent":     "systemd",
        "event_type": "CONNECT",
        "target":     "192.168.10.55:22",
        "user":       "root",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(2),
        "host":       "auth-server",
        "pid":        2002,
        "ppid":       2001,
        "process":    "bash",
        "parent":     "sshd",
        "event_type": "SPAWN",
        "target":     "bash",
        "user":       "admin",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(8),
        "host":       "auth-server",
        "pid":        2002,
        "ppid":       2001,
        "process":    "bash",
        "parent":     "sshd",
        "event_type": "READ",
        "target":     "/etc/passwd",
        "user":       "admin",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(12),
        "host":       "auth-server",
        "pid":        2002,
        "ppid":       2001,
        "process":    "bash",
        "parent":     "sshd",
        "event_type": "CONNECT",
        "target":     "db-server:5432",
        "user":       "admin",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(20),
        "host":       "db-server",
        "pid":        3001,
        "ppid":       1,
        "process":    "psql",
        "parent":     "systemd",
        "event_type": "READ",
        "target":     "customers_pii_table",
        "user":       "admin",
    },
]


# ── Scenario 3: Ransomware File Encryption ──────────────────────────────────
SCENARIO_RANSOMWARE = [
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(0),
        "host":       "workstation-2",
        "pid":        4001,
        "ppid":       900,
        "process":    "update.exe",
        "parent":     "explorer.exe",
        "event_type": "SPAWN",
        "target":     "vssadmin.exe",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(3),
        "host":       "workstation-2",
        "pid":        4002,
        "ppid":       4001,
        "process":    "vssadmin.exe",
        "parent":     "update.exe",
        "event_type": "DELETE",
        "target":     "shadow copies",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(6),
        "host":       "workstation-2",
        "pid":        4001,
        "ppid":       900,
        "process":    "update.exe",
        "parent":     "explorer.exe",
        "event_type": "WRITE",
        "target":     "C:\\Users\\Documents\\report.docx.locked",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(7),
        "host":       "workstation-2",
        "pid":        4001,
        "ppid":       900,
        "process":    "update.exe",
        "parent":     "explorer.exe",
        "event_type": "WRITE",
        "target":     "C:\\Users\\Documents\\spreadsheet.xlsx.locked",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(8),
        "host":       "workstation-2",
        "pid":        4001,
        "ppid":       900,
        "process":    "update.exe",
        "parent":     "explorer.exe",
        "event_type": "WRITE",
        "target":     "C:\\README_RANSOM.txt",
        "user":       "standard_user",
    },
    {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts(10),
        "host":       "workstation-2",
        "pid":        4001,
        "ppid":       900,
        "process":    "update.exe",
        "parent":     "explorer.exe",
        "event_type": "CONNECT",
        "target":     "93.184.216.34:80",
        "user":       "standard_user",
    },
]


ALL_SCENARIOS = {
    "apt_phishing":      SCENARIO_APT_PHISHING,
    "lateral_movement":  SCENARIO_LATERAL_MOVEMENT,
    "ransomware":        SCENARIO_RANSOMWARE,
}
