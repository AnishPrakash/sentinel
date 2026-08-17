# backend/layer4_symbolic/privilege_checker.py
"""
Checks whether the user/process involved has the required privilege
to perform the claimed action.
"""
from typing import List, Tuple

# Privilege model: technique_id → required_privilege_level
# Level: 0=any user, 1=standard user, 2=admin, 3=SYSTEM/root
TECHNIQUE_PRIVILEGE_REQUIREMENTS = {
    "T1053": 2,   # Scheduled Task — requires admin
    "T1548": 3,   # Abuse Elevation Control — requires SYSTEM
    "T1134": 3,   # Access Token Manipulation — SYSTEM
    "T1078": 1,   # Valid Accounts — standard user
    "T1059": 1,   # Command Interpreter — standard user
    "T1566": 0,   # Phishing — any
    "T1110": 0,   # Brute Force — network level
    "T1021": 1,   # Remote Services — standard user
}

USER_PRIVILEGE_LEVELS = {
    "SYSTEM":         3,
    "root":           3,
    "Administrator":  2,
    "admin":          2,
    "standard_user":  1,
    "guest":          0,
}


class PrivilegeConstraintChecker:

    def get_user_level(self, user: str) -> int:
        return USER_PRIVILEGE_LEVELS.get(user, 1)   # default: standard

    def check(
        self, technique_id: str, user: str
    ) -> Tuple[bool, str]:
        """
        Returns (valid: bool, issue_description: str).
        """
        required = TECHNIQUE_PRIVILEGE_REQUIREMENTS.get(technique_id, 0)
        actual   = self.get_user_level(user)
        if actual < required:
            return False, (
                f"Privilege violation: {technique_id} requires level {required} "
                f"but user '{user}' has level {actual}."
            )
        return True, ""

    def check_narrative_techniques(
        self, techniques: List[dict], user: str
    ) -> Tuple[bool, List[str]]:
        issues = []
        for t in techniques:
            tid = t.get("technique_id", "")
            valid, issue = self.check(tid, user)
            if not valid:
                issues.append(issue)
        return len(issues) == 0, issues
