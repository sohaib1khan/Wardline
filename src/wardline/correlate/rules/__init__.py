"""One module per correlation rule."""

from __future__ import annotations

from wardline.correlate.rules.base import Rule, RuleOutcome
from wardline.correlate.rules.r1_backport import R1BackportCheck
from wardline.correlate.rules.r2_changed_binary import R2ChangedBinary
from wardline.correlate.rules.r3_lynis_trivy import R3LynisTrivy
from wardline.correlate.rules.r4_exposed_service import R4ExposedService
from wardline.correlate.rules.r5_patched_not_active import R5PatchedNotActive
from wardline.correlate.rules.r6_account_tampering import R6AccountTampering
from wardline.correlate.rules.r7_malware_persistence import R7MalwarePersistence

ALL_RULES: list[Rule] = [
    R1BackportCheck(),
    R2ChangedBinary(),
    R3LynisTrivy(),
    R4ExposedService(),
    R5PatchedNotActive(),
    R6AccountTampering(),
    R7MalwarePersistence(),
]

__all__ = [
    "ALL_RULES",
    "R1BackportCheck",
    "R2ChangedBinary",
    "R3LynisTrivy",
    "R4ExposedService",
    "R5PatchedNotActive",
    "R6AccountTampering",
    "R7MalwarePersistence",
    "Rule",
    "RuleOutcome",
]
