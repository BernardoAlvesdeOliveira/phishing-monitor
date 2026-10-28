import logging

from app.services.dkim_analyzer import DkimAnalyzer
from app.services.dns_analyzer import DnsAnalyzer
from app.services.email_parser import EmailParser, ParsedEmail
from app.services.risk_engine import RiskEngine, RiskResult
from app.services.url_analyzer import UrlAnalyzer

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    def __init__(self, parser: EmailParser | None = None, url_analyzer: UrlAnalyzer | None = None,
                 dkim_analyzer: DkimAnalyzer | None = None, dns_analyzer: DnsAnalyzer | None = None,
                 risk_engine: RiskEngine | None = None):
        self.parser = parser or EmailParser()
        self.url_analyzer = url_analyzer or UrlAnalyzer()
        self.dkim_analyzer = dkim_analyzer or DkimAnalyzer()
        self.dns_analyzer = dns_analyzer or DnsAnalyzer()
        self.risk_engine = risk_engine or RiskEngine()

    def analyze(self, raw_email: str, *, sender: str = "", recipient: str = "", subject: str = "") -> tuple[ParsedEmail, RiskResult]:
        email = self.parser.parse(raw_email, fallback_sender=sender, fallback_recipient=recipient, fallback_subject=subject)
        findings = self.url_analyzer.analyze(email.urls)
        dkim_findings, dkim_available = self.dkim_analyzer.analyze(email)
        dns_findings, dns_available = self.dns_analyzer.analyze(email)
        findings.extend(dkim_findings)
        findings.extend(dns_findings)
        result = self.risk_engine.evaluate(findings, verification_available=dkim_available or dns_available)
        logger.info("email analysis complete message_id=%s score=%s level=%s", email.message_id, result.score, result.level)
        return email, result