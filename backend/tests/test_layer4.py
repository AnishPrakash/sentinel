# tests/test_layer4.py
import pytest
from layer4_symbolic.network_checker   import NetworkReachabilityChecker
from layer4_symbolic.privilege_checker import PrivilegeConstraintChecker
from layer4_symbolic.temporal_checker  import TemporalConsistencyChecker
from layer4_symbolic.symbolic_validator import SymbolicValidator


def test_network_reachability_valid():
    checker = NetworkReachabilityChecker()
    assert checker.can_reach("workstation-1", "auth-server", 445) is True


def test_network_reachability_blocked():
    checker = NetworkReachabilityChecker()
    assert checker.can_reach("workstation-1", "db-server") is False


def test_privilege_check_system_ok():
    checker = PrivilegeConstraintChecker()
    valid, issue = checker.check("T1053", "SYSTEM")
    assert valid is True


def test_privilege_check_standard_user_fail():
    checker = PrivilegeConstraintChecker()
    valid, issue = checker.check("T1053", "standard_user")
    assert valid is False
    assert "Privilege violation" in issue


def test_temporal_ordering_valid():
    checker = TemporalConsistencyChecker()
    events = [
        {"description": "process spawn", "timestamp": "1000"},
        {"description": "file write",    "timestamp": "1005"},
        {"description": "net connect",   "timestamp": "1010"},
    ]
    valid, issues = checker.check_sequence(events)
    assert valid is True


def test_temporal_ordering_invalid():
    checker = TemporalConsistencyChecker()
    events = [
        {"description": "exfiltration", "timestamp": "1000"},
        {"description": "process spawn","timestamp": "500"},   # Before!
    ]
    valid, issues = checker.check_sequence(events)
    assert valid is False


def test_full_validator_valid():
    sv = SymbolicValidator()
    narrative = {
        "lateral_steps": [
            {"src_host": "workstation-1", "dst_host": "auth-server",
             "port": 445, "technique": "SMB"}
        ],
        "matched_techniques": [{"technique_id": "T1059"}],
        "event_sequence": [
            {"description": "spawn",   "timestamp": "1000"},
            {"description": "connect", "timestamp": "1010"},
        ]
    }
    result = sv.validate(narrative, user="standard_user")
    assert result.status in ("VALID", "PARTIAL")
