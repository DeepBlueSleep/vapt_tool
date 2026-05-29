from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    EXECUTIVE = "executive"
    ENGINEER = "engineer"
    SECURITY_ANALYST = "security_analyst"
    COMPLIANCE_AUDITOR = "compliance_auditor"


@dataclass(frozen=True)
class User:
    username: str
    role: Role = Role.SECURITY_ANALYST
