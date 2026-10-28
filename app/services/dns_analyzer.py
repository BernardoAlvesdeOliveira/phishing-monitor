from app.services.email_parser import ParsedEmail
from app.services.risk_engine import Finding


class DnsAnalyzer:
    def analyze(self, email: ParsedEmail) -> tuple[list[Finding], bool]:
        domain = email.sender.rsplit("@", 1)[-1] if "@" in email.sender else ""
        if not domain:
            return [Finding("sender_domain_unavailable", "Sender domain was unavailable for DNS analysis.", "low", 0)], False
        return [Finding("dns_unavailable", f"SPF and DMARC could not be verified for {domain}.", "low", 0)], False