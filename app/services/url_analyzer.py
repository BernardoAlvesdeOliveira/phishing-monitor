import ipaddress
from urllib.parse import urlsplit

from app.services.risk_engine import Finding


class UrlAnalyzer:
    def __init__(self, trusted_domains: set[str] | None = None, threat_indicators: set[str] | None = None):
        self.trusted_domains = {domain.lower().strip(".") for domain in (trusted_domains or set())}
        self.threat_indicators = {indicator.lower() for indicator in (threat_indicators or set())}

    def analyze(self, urls: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for url in urls:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if not host or parsed.scheme.lower() not in {"http", "https"}:
                findings.append(Finding("malformed_url", "Malformed or unsupported URL detected.", "medium", 15, url))
                continue
            if url.lower() in self.threat_indicators or host in self.threat_indicators:
                findings.append(Finding("threat_intelligence_match", "URL matched a configured threat intelligence indicator.", "critical", 75, host, True))
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address:
                findings.append(Finding("url_ip_host", "URL uses an IP address directly as its host.", "high", 25, host))
                if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                    findings.append(Finding("restricted_url_host", "URL points to a restricted or internal IP address.", "critical", 50, host))
            if host.startswith("xn--") or ".xn--" in host:
                findings.append(Finding("punycode_domain", "URL uses a punycode internationalized domain.", "medium", 15, host))
            if len(url) > 200 or "@" in parsed.netloc:
                findings.append(Finding("unusual_url_structure", "URL has an unusual structure that can obscure its destination.", "medium", 15, url))
            registrable = self._registrable_domain(host)
            if self.trusted_domains and registrable not in self.trusted_domains and any(
                self._similar_domain(registrable, trusted) for trusted in self.trusted_domains
            ):
                findings.append(Finding("possible_typosquatting", "URL domain is similar to a configured trusted domain.", "medium", 20, registrable))
        return findings

    @staticmethod
    def _registrable_domain(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    @staticmethod
    def _similar_domain(left: str, right: str) -> bool:
        left_name, _, left_tld = left.partition(".")
        right_name, _, right_tld = right.partition(".")
        if left_tld != right_tld or left_name == right_name:
            return False
        return len(left_name) >= 4 and (
            left_name in right_name or right_name in left_name or UrlAnalyzer._levenshtein(left_name, right_name) <= 1
        )

    @staticmethod
    def _levenshtein(left: str, right: str) -> int:
        previous = list(range(len(right) + 1))
        for index, char in enumerate(left, 1):
            current = [index]
            for other_index, other in enumerate(right, 1):
                current.append(min(current[-1] + 1, previous[other_index] + 1, previous[other_index - 1] + (char != other)))
            previous = current
        return previous[-1]