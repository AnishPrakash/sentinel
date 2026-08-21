# backend/layer1_ingestion/log_parser.py
"""
Parses raw log events (Sysmon XML format or BETH-style JSON)
into unified LogEvent objects that feed the provenance graph.
"""
import xml.etree.ElementTree as ET
import json
from typing import List, Optional
from models.schemas import LogEvent, EdgeType


# ─── Sysmon EventID → EdgeType mapping ──────────────────────────────────────
SYSMON_EVENT_MAP = {
    1:  EdgeType.SPAWN,       # Process Create
    11: EdgeType.WRITE,       # File Create
    12: EdgeType.MODIFY_REG,  # Registry Create/Delete
    13: EdgeType.MODIFY_REG,  # Registry Set Value
    3:  EdgeType.CONNECT,     # Network Connection
    23: EdgeType.DELETE,      # File Delete
    15: EdgeType.READ,        # File Create Stream Hash (proxy for read)
}


def parse_sysmon_xml(xml_string: str) -> Optional[LogEvent]:
    """
    Parse a single Sysmon XML event string into a LogEvent.
    Returns None if event type is not mapped.
    """
    try:
        root = ET.fromstring(xml_string)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        event_id = int(root.find(".//e:EventID", ns).text)
        if event_id not in SYSMON_EVENT_MAP:
            return None

        system  = root.find("e:System", ns)
        data    = {d.get("Name"): d.text for d in root.findall(".//e:Data", ns)}

        return LogEvent(
            timestamp  = system.find("e:TimeCreated", ns).get("SystemTime", ""),
            host       = system.find("e:Computer", ns).text or "unknown",
            pid        = int(data.get("ProcessId", 0)),
            ppid       = int(data.get("ParentProcessId", 0)),
            process    = data.get("Image", "unknown").split("\\")[-1],
            parent     = data.get("ParentImage", "unknown").split("\\")[-1],
            event_type = SYSMON_EVENT_MAP[event_id],
            target     = (
                data.get("TargetFilename") or
                data.get("TargetObject") or
                f"{data.get('DestinationIp','?')}:{data.get('DestinationPort','?')}"
            ),
            user       = data.get("User", "SYSTEM"),
        )
    except Exception as e:
        print(f"[Parser] Sysmon parse error: {e}")
        return None


def parse_beth_row(row: dict) -> Optional[LogEvent]:
    """
    Parse a single row from the BETH dataset (Kaggle version).
    Columns: timestamp, processId, parentProcessId, userId, hostName,
             processName, eventName, args, sus, evil
    """
    # Use eventName first, fall back to args content for edge type
    event_name = str(row.get("eventName", "")).lower()
    args = str(row.get("args", ""))

    combined = event_name + args.lower()

    if any(k in combined for k in ("execve", "fork", "clone")):
        edge = EdgeType.SPAWN
    elif any(k in combined for k in ("read", "open")):
        edge = EdgeType.READ
    elif any(k in combined for k in ("write", "creat")):
        edge = EdgeType.WRITE
    elif any(k in combined for k in ("connect", "socket", "sendto")):
        edge = EdgeType.CONNECT
    elif any(k in combined for k in ("unlink", "rmdir")):
        edge = EdgeType.DELETE
    else:
        edge = EdgeType.READ  # default fallback

    try:
        pid  = int(row.get("processId", 0))
        ppid = int(row.get("parentProcessId", 0))
        return LogEvent(
            timestamp  = str(row.get("timestamp", "0")),
            host       = str(row.get("hostName", "honeypot-1")),
            pid        = pid,
            ppid       = ppid,
            process    = str(row.get("processName", f"proc_{pid}")),
            parent     = f"proc_{ppid}",
            event_type = edge,
            target     = args[:128],
            user       = str(row.get("userId", "root")),
        )
    except Exception as e:
        print(f"[Parser] BETH parse error: {e}")
        return None


def parse_json_batch(raw_json: str) -> List[LogEvent]:
    """
    Accept a JSON array of log dicts (our REST /ingest/logs format).
    Each dict should already conform to LogEvent fields.
    """
    try:
        items = json.loads(raw_json)
        events = []
        for item in items:
            try:
                events.append(LogEvent(**item))
            except Exception as e:
                print(f"[Parser] Schema validation skip: {e}")
        return events
    except json.JSONDecodeError as e:
        print(f"[Parser] JSON decode error: {e}")
        return []
