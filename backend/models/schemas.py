# backend/models/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid
from datetime import datetime


class EdgeType(str, Enum):
    SPAWN   = "SPAWN"
    READ    = "READ"
    WRITE   = "WRITE"
    CONNECT = "CONNECT"
    DELETE  = "DELETE"
    MODIFY_REG = "MODIFY_REG"


class LogEvent(BaseModel):
    event_id:   str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:  str
    host:       str
    pid:        int
    ppid:       int
    process:    str
    parent:     str
    event_type: EdgeType
    target:     str          # file path / IP:port / registry key
    user:       str = "SYSTEM"


class IngestRequest(BaseModel):
    logs: List[LogEvent]


class GraphNode(BaseModel):
    id:           str
    label:        str
    node_type:    str          # process | file | socket | registry | user
    host:         str
    anomaly_score: float = 0.0


class GraphEdge(BaseModel):
    source:    str
    target:    str
    edge_type: EdgeType
    timestamp: str


class GraphSnapshot(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class MitreMatch(BaseModel):
    technique_id:   str
    technique_name: str
    tactic:         str
    confidence:     float


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class ValidationResult(BaseModel):
    status:      str          # VALID | PARTIAL | INVALID
    issues:      List[str] = []
    reprompted:  bool = False


class Alert(BaseModel):
    alert_id:         str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:        str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    host:             str
    risk_score:       float
    severity:         AlertSeverity
    anomaly_score:    float
    narrative:        str = ""
    mitre_matches:    List[MitreMatch] = []
    predicted_next:   str = ""
    validation:       Optional[ValidationResult] = None
    playbook_actions: List[str] = []
    status:           str = "OPEN"   # OPEN | ACTIONED | DISMISSED


class ActionRequest(BaseModel):
    action: str
    approved_by: Optional[str] = None


class ActionResult(BaseModel):
    alert_id:  str
    action:    str
    executed:  bool
    message:   str
    timestamp: str
