# tests/test_layer1.py
import pytest
from layer1_ingestion.log_parser import parse_beth_row, parse_sysmon_xml
from layer1_ingestion.graph_builder import ProvenanceGraph
from models.schemas import EdgeType


def test_parse_beth_row_spawn():
    row = {"timestamp": "1000", "host": "h1", "pid": 100, "ppid": 50,
           "args": "execve /bin/bash", "sus": "0"}
    event = parse_beth_row(row)
    assert event is not None
    assert event.event_type == EdgeType.SPAWN


def test_parse_beth_row_connect():
    row = {"timestamp": "1001", "host": "h1", "pid": 101, "ppid": 50,
           "args": "connect 8.8.8.8:80", "sus": "1"}
    event = parse_beth_row(row)
    assert event is not None
    assert event.event_type == EdgeType.CONNECT


def test_provenance_graph_add():
    pg = ProvenanceGraph()
    row = {"timestamp": "1002", "host": "h1", "pid": 200, "ppid": 100,
           "args": "write /tmp/evil.sh", "sus": "1"}
    event = parse_beth_row(row)
    src, tgt = pg.add_event(event)
    assert pg.node_count() >= 2
    assert pg.edge_count() >= 1


def test_graph_snapshot():
    pg = ProvenanceGraph()
    row = {"timestamp": "1003", "host": "h2", "pid": 300, "ppid": 200,
           "args": "execve /bin/sh", "sus": "0"}
    event = parse_beth_row(row)
    pg.add_event(event)
    snap = pg.get_snapshot()
    assert len(snap.nodes) > 0
    assert len(snap.edges) > 0
