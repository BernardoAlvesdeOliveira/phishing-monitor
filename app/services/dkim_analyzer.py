from app.services.email_parser import ParsedEmail
from app.services.risk_engine import Finding


class DkimAnalyzer:
    def analyze(self, email: ParsedEmail) -> tuple[list[Finding], bool]:
        if not email.headers.get("dkim-signature"):
            return [Finding("dkim_missing", "DKIM signature was not present; this is inconclusive.", "low", 0)], False
        return [Finding("dkim_unverified", "DKIM signature was present but cryptographic verification is unavailable.", "low", 0)], False