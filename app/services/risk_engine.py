from dataclasses import dataclass, field
from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalysisStatus(StrEnum):
    ASSESSED = "ASSESSED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class Finding:
    code: str
    description: str
    severity: str
    points: int
    evidence: str | None = None
    confirmed: bool = False


@dataclass
class RiskResult:
    score: int
    level: RiskLevel
    status: AnalysisStatus
    findings: list[Finding] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)


class RiskEngine:
    def evaluate(self, findings: list[Finding], *, verification_available: bool) -> RiskResult:
        unique: dict[str, Finding] = {}
        for finding in findings:
            unique.setdefault(finding.code, finding)
        selected = list(unique.values())
        score = min(100, max(0, sum(finding.points for finding in selected)))
        if score >= 75:
            level = RiskLevel.CRITICAL
        elif score >= 50:
            level = RiskLevel.HIGH
        elif score >= 25:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        status = AnalysisStatus.ASSESSED if verification_available else AnalysisStatus.INCONCLUSIVE
        return RiskResult(score, level, status, selected, [f.description for f in selected])