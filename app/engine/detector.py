"""
PhishingDetector — Industry-Grade URL Threat Analysis Engine v2.0
=================================================================
Multi-layer signal architecture:
  - Lexical analysis   (keywords, length, special chars)
  - Structural analysis (IP, TLD, subdomain depth, ports)
  - Brand intelligence  (impersonation, combo-squatting, brand-as-subdomain)
  - Typosquatting       (leet-speak normalisation, homoglyph map, similarity)
  - DGA detection       (entropy, vowel ratio, consonant clusters)
  - Obfuscation         (hex encoding, data: URIs, base64 in query)
  - Redirect detection  (open redirect params, double-slash, @ symbol)

Scoring: sum(signal.score * signal.confidence) capped at 100
Each signal carries an independent confidence weight to reduce false positives.
"""

from __future__ import annotations

import re
import math
import time
import logging
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, unquote, parse_qs
from collections import Counter

from app.models.schemas import Verdict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Threat category taxonomy
# ---------------------------------------------------------------------------

class ThreatCategory(str, Enum):
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BRAND_IMPERSONATION   = "brand_impersonation"
    TYPOSQUATTING         = "typosquatting"
    HOMOGRAPH_ATTACK      = "homograph_attack"
    OPEN_REDIRECT         = "open_redirect"
    MALWARE_DELIVERY      = "malware_delivery"
    DGA_DOMAIN            = "dga_domain"
    OBFUSCATION           = "obfuscation"
    DATA_EXFILTRATION     = "data_exfiltration"
    SUSPICIOUS_STRUCTURE  = "suspicious_structure"


# ---------------------------------------------------------------------------
# Signal dataclass — full audit trail per detection
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    name:       str
    score:      int           # raw weight (0-100 scale)
    reason:     str
    category:   ThreatCategory
    confidence: float = 1.0  # 0.0-1.0; reduces FP risk for noisy signals
    evidence:   Optional[str] = None


# ---------------------------------------------------------------------------
# AnalysisResult — structured return value
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    verdict:           Verdict
    confidence:        int
    reasons:           list
    signals:           list = field(default_factory=list)
    threat_categories: list = field(default_factory=list)
    domain:            str  = ""
    tld:               str  = ""
    is_ip:             bool = False
    is_idn:            bool = False
    subdomain_depth:   int  = 0
    entropy:           float = 0.0
    analysis_time_ms:  float = 0.0
    url_decoded:       str  = ""

    def to_dict(self) -> dict:
        return {
            "verdict":           self.verdict,
            "confidence":        self.confidence,
            "reasons":           self.reasons,
            "threat_categories": self.threat_categories,
            "domain":            self.domain,
            "tld":               self.tld,
            "is_ip":             self.is_ip,
            "is_idn":            self.is_idn,
            "subdomain_depth":   self.subdomain_depth,
            "entropy":           round(self.entropy, 4),
            "analysis_time_ms":  round(self.analysis_time_ms, 3),
            "url_decoded":       self.url_decoded,
            "signals": [
                {
                    "name":       s.name,
                    "score":      s.score,
                    "reason":     s.reason,
                    "category":   s.category.value,
                    "confidence": s.confidence,
                    "evidence":   s.evidence,
                }
                for s in self.signals
            ],
        }


# ---------------------------------------------------------------------------
# PhishingDetector
# ---------------------------------------------------------------------------

class PhishingDetector:
    """
    Multi-signal phishing detector.

    Verdict thresholds (override via class attributes):
        PHISHING     >= 60
        SUSPICIOUS   >= 30
        SAFE          < 30
    """

    # ── Threat intelligence data ────────────────────────────────────────────

    KEYWORDS_CREDENTIAL = frozenset({
        "login", "signin", "sign-in", "verify", "verification",
        "secure", "security", "account", "update", "banking",
        "confirm", "wallet", "password", "credential", "credentials",
        "authenticate", "authentication", "unlock", "reactivate",
        "billing", "support", "helpdesk", "2fa", "otp", "token",
        "suspended", "unusual", "activity", "validate", "urgent",
        "alert", "notice", "access", "identity", "ssn", "irs",
        "reset", "recovery", "reverify", "expire", "expiry",
    })

    KEYWORDS_MALWARE = frozenset({
        "download", "install", "setup", "update", "patch",
        "crack", "keygen", "free", "serial", "activation",
        "payload", "dropper", "loader",
    })

    # (canonical_name, official_registrable_domain)
    BRANDS: list = [
        ("google",        "google.com"),
        ("paypal",        "paypal.com"),
        ("facebook",      "facebook.com"),
        ("microsoft",     "microsoft.com"),
        ("amazon",        "amazon.com"),
        ("apple",         "apple.com"),
        ("instagram",     "instagram.com"),
        ("linkedin",      "linkedin.com"),
        ("github",        "github.com"),
        ("netflix",       "netflix.com"),
        ("twitter",       "twitter.com"),
        ("dropbox",       "dropbox.com"),
        ("yahoo",         "yahoo.com"),
        ("outlook",       "outlook.com"),
        ("office365",     "office.com"),
        ("onedrive",      "onedrive.com"),
        ("wellsfargo",    "wellsfargo.com"),
        ("bankofamerica", "bankofamerica.com"),
        ("chase",         "chase.com"),
        ("citibank",      "citibank.com"),
        ("steam",         "steampowered.com"),
        ("discord",       "discord.com"),
        ("tiktok",        "tiktok.com"),
        ("whatsapp",      "whatsapp.com"),
        ("ebay",          "ebay.com"),
        ("adobe",         "adobe.com"),
        ("docusign",      "docusign.com"),
        ("coinbase",      "coinbase.com"),
        ("binance",       "binance.com"),
        ("dhl",           "dhl.com"),
        ("fedex",         "fedex.com"),
        ("ups",           "ups.com"),
        ("irs",           "irs.gov"),
        ("usps",          "usps.com"),
        ("zelle",         "zellepay.com"),
        ("venmo",         "venmo.com"),
    ]

    SUSPICIOUS_TLDS = frozenset({
        ".xyz", ".top", ".club", ".win", ".gq", ".cc",
        ".tk", ".ml", ".ga", ".cf", ".pw", ".su",
        ".buzz", ".click", ".link", ".live", ".online",
        ".site", ".website", ".icu", ".cam", ".vip",
        ".loan", ".work", ".party", ".review", ".stream",
        ".download", ".racing", ".science", ".trade",
        ".bid", ".faith", ".date", ".accountant",
        ".bd", ".ke",
    })

    ALLOWLIST = frozenset({
        "google.com", "github.com", "microsoft.com", "apple.com",
        "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
        "paypal.com", "netflix.com", "instagram.com", "yahoo.com",
        "outlook.com", "live.com", "office.com", "onedrive.com",
        "discord.com", "dropbox.com", "twitch.tv", "reddit.com",
        "youtube.com", "wikipedia.org", "cloudflare.com", "amazonaws.com",
        "azure.com", "stackoverflow.com", "mozilla.org",
    })

    TYPO_MAP: dict = {
        "0": "o", "1": "l", "3": "e", "4": "a",
        "5": "s", "6": "g", "7": "t", "8": "b",
        "9": "g", "@": "a", "$": "s", "!": "i",
        "vv": "w", "rn": "m",
    }

    HOMOGLYPH_MAP: dict = {
        "\u0430": "a", "\u0435": "e", "\u043e": "o",
        "\u0440": "p", "\u0441": "c",                  # Cyrillic
        "\u03bf": "o", "\u03c1": "p", "\u03b1": "a",   # Greek
        "\u217c": "l", "\u2170": "i",                   # Roman numerals
        "\u1e21": "g", "\u1e41": "m", "\u1e45": "n",   # Diacritics
    }

    REDIRECT_PARAMS = frozenset({
        "redirect", "url", "return", "next", "goto",
        "target", "redir", "forward", "callback", "continue",
        "dest", "destination", "location", "link", "ref",
    })

    MALWARE_EXTENSIONS = frozenset({
        ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jar", ".scr", ".hta", ".pif", ".com",
        ".reg", ".dll", ".apk", ".dmg", ".iso",
    })

    HARVEST_PAGES = frozenset({
        "login", "signin", "sign-in", "logon", "log-in",
        "verify", "verification", "validate", "confirm",
        "secure", "security", "account", "auth", "authenticate",
        "credential", "update", "password", "passwd",
    })

    DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "blob"})

    # Compiled class-level regexes (created once, not per call)
    _RE_IP           = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    _RE_HEX          = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")
    _RE_PORT         = re.compile(r":(\d{2,5})(?:/|$)")
    _RE_SCHEME       = re.compile(r"^([a-z][a-z0-9+\-.]*):.*", re.IGNORECASE)
    _RE_PUNYCODE     = re.compile(r"xn--", re.IGNORECASE)
    _RE_LONG_NUM     = re.compile(r"\d{8,}")
    _RE_CONSONANTS   = re.compile(r"[^aeiou]{6,}")
    _RE_B64          = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    _RE_DOUBLE_SLASH = re.compile(r"(?:https?:)?//.*//")

    # Verdict thresholds
    THRESHOLD_PHISHING   = 60
    THRESHOLD_SUSPICIOUS = 30

    # ── Constructor ─────────────────────────────────────────────────────────

    def __init__(self):
        self._brand_map: dict   = {b: d for b, d in self.BRANDS}
        self._brand_names: list = [b for b, _ in self.BRANDS]
        self._official_domains  = frozenset(d for _, d in self.BRANDS)

    # ── Utility helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _normalize_unicode(text: str) -> str:
        return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio()

    def _normalize_typo(self, text: str) -> str:
        for k, v in self.TYPO_MAP.items():
            text = text.replace(k, v)
        return text

    def _apply_homoglyphs(self, text: str) -> str:
        return "".join(self.HOMOGLYPH_MAP.get(c, c) for c in text)

    @staticmethod
    def _registrable_domain(domain: str) -> str:
        """Naïve eTLD+1 — handles common two-part eTLDs (co.uk, com.au …)."""
        two_part = {"co", "com", "org", "net", "gov", "edu", "ac", "ne", "or"}
        parts = domain.split(".")
        if len(parts) >= 3 and parts[-2] in two_part:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    @staticmethod
    def _tld(domain: str) -> str:
        parts = domain.split(".")
        return ("." + parts[-1]) if parts else ""

    @staticmethod
    def _subdomain_depth(domain: str) -> int:
        return max(domain.count(".") - 1, 0)

    def _is_dga(self, label: str) -> bool:
        """Heuristic DGA: high entropy + unpronounceable / numeric-heavy."""
        if len(label) < 7:
            return False
        entropy      = self._shannon_entropy(label)
        vowel_ratio  = sum(c in "aeiou" for c in label) / len(label)
        has_cluster  = bool(self._RE_CONSONANTS.search(label))
        has_long_num = bool(self._RE_LONG_NUM.search(label))
        return entropy > 3.8 and (vowel_ratio < 0.20 or has_cluster or has_long_num)

    # ── Core analysis ────────────────────────────────────────────────────────

    def analyze(self, url: str) -> dict:
        """
        Analyse a URL for phishing signals.
        Returns a dict (backward-compatible with original API contract).
        Rich fields are present in addition to verdict / confidence / reasons.
        """
        t0 = time.perf_counter()
        signals: list        = []
        categories: set      = set()

        def emit(sig: Signal) -> None:
            signals.append(sig)
            categories.add(sig.category)

        # ── Guard: empty / None ──────────────────────────────────────────────
        if not url or not url.strip():
            return AnalysisResult(
                verdict=Verdict.SAFE, confidence=0,
                reasons=["Empty URL provided"],
            ).to_dict()

        url = url.strip()

        # ── 1. Dangerous URI scheme → instant block ──────────────────────────
        m = self._RE_SCHEME.match(url)
        if m and m.group(1).lower() in self.DANGEROUS_SCHEMES:
            scheme = m.group(1).lower()
            return AnalysisResult(
                verdict=Verdict.PHISHING, confidence=100,
                reasons=[f"Dangerous URI scheme '{scheme}:' — execution risk"],
                threat_categories=[ThreatCategory.OBFUSCATION.value],
                analysis_time_ms=(time.perf_counter() - t0) * 1000,
            ).to_dict()

        # ── 2. Parse & decode ────────────────────────────────────────────────
        try:
            url_decoded = unquote(url)
            effective   = url_decoded if "://" in url_decoded else "http://" + url_decoded
            parsed      = urlparse(effective)
            raw_netloc  = parsed.netloc.lower()
            path        = parsed.path.lower()
            query_str   = parsed.query.lower()
            fragment    = parsed.fragment.lower()
        except Exception as exc:
            logger.warning("URL parse error for %r: %s", url, exc)
            raw_netloc = url.lower()
            path = query_str = fragment = ""
            url_decoded = url

        domain      = raw_netloc.split(":")[0].replace("www.", "")
        ascii_dom   = self._normalize_unicode(domain)
        homo_dom    = self._apply_homoglyphs(domain)
        reg_dom     = self._registrable_domain(domain)
        tld         = self._tld(domain)
        base        = domain.split(".")[0]
        subdepth    = self._subdomain_depth(domain)
        entropy_val = self._shannon_entropy(ascii_dom)
        full_text   = " ".join([path, query_str, fragment])

        # ── 3. Allowlist ─────────────────────────────────────────────────────
        if (domain in self.ALLOWLIST or reg_dom in self.ALLOWLIST
                or any(domain.endswith("." + d) for d in self.ALLOWLIST)):
            return AnalysisResult(
                verdict=Verdict.SAFE, confidence=0,
                reasons=["Domain is in the trusted allowlist"],
                domain=domain, tld=tld,
                analysis_time_ms=(time.perf_counter() - t0) * 1000,
            ).to_dict()

        # ── 4. Raw IP address ────────────────────────────────────────────────
        is_ip = bool(self._RE_IP.match(domain))
        if is_ip:
            emit(Signal("raw_ip", 80,
                        "Raw IP address used instead of a domain name — common in phishing",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.99, domain))

        # ── 5. Punycode / IDN ────────────────────────────────────────────────
        is_idn = bool(self._RE_PUNYCODE.search(domain))
        if is_idn:
            emit(Signal("idn_punycode", 35,
                        "Internationalized domain (IDN/Punycode) — possible homograph attack",
                        ThreatCategory.HOMOGRAPH_ATTACK, 0.75, domain))

        # ── 6. Unicode homoglyph ─────────────────────────────────────────────
        if domain != ascii_dom:
            emit(Signal("unicode_homoglyph", 45,
                        "Unicode characters visually resembling ASCII found in domain",
                        ThreatCategory.HOMOGRAPH_ATTACK, 0.90, domain))
        elif homo_dom != domain:
            emit(Signal("homoglyph_substitution", 40,
                        "Known visual lookalike characters (Cyrillic/Greek) detected in domain",
                        ThreatCategory.HOMOGRAPH_ATTACK, 0.85, domain))

        # ── 7. URL length tiers ───────────────────────────────────────────────
        url_len = len(url)
        if url_len > 250:
            emit(Signal("url_extreme_length", 25, f"URL is extremely long ({url_len} chars)",
                        ThreatCategory.OBFUSCATION, 0.70))
        elif url_len > 100:
            emit(Signal("url_long", 15, f"URL is long ({url_len} chars)",
                        ThreatCategory.OBFUSCATION, 0.50))
        elif url_len > 75:
            emit(Signal("url_moderate_length", 8, f"URL is moderately long ({url_len} chars)",
                        ThreatCategory.OBFUSCATION, 0.35))

        # ── 8. @ symbol ───────────────────────────────────────────────────────
        if "@" in url:
            emit(Signal("at_symbol", 65,
                        "URL contains '@' — browsers treat everything before it as credentials",
                        ThreatCategory.CREDENTIAL_HARVESTING, 0.95))

        # ── 9. Double-slash redirect ──────────────────────────────────────────
        if self._RE_DOUBLE_SLASH.search(url):
            emit(Signal("double_slash", 40,
                        "Unexpected '//' after scheme — open redirect or URL confusion",
                        ThreatCategory.OPEN_REDIRECT, 0.80))

        # ── 10. Hex / percent-encoding obfuscation ────────────────────────────
        hex_hits = self._RE_HEX.findall(url)
        if hex_hits:
            emit(Signal("hex_obfuscation", 35,
                        f"Multiple percent-encoded sequences ({len(hex_hits)}) — obfuscation indicator",
                        ThreatCategory.OBFUSCATION, 0.80, str(hex_hits[:3])))

        # ── 11. Non-standard port ─────────────────────────────────────────────
        port_m = self._RE_PORT.search(raw_netloc)
        if port_m:
            port = int(port_m.group(1))
            if port not in {80, 443, 8080, 8443, 8000, 3000}:
                emit(Signal("nonstandard_port", 20,
                            f"Non-standard port {port} — unusual for public-facing services",
                            ThreatCategory.SUSPICIOUS_STRUCTURE, 0.60, str(port)))

        # ── 12. Suspicious TLD ────────────────────────────────────────────────
        if tld in self.SUSPICIOUS_TLDS:
            emit(Signal("suspicious_tld", 25,
                        f"High-abuse TLD '{tld}' disproportionately used in phishing campaigns",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.65, tld))

        # ── 13. Subdomain depth ───────────────────────────────────────────────
        if subdepth >= 4:
            emit(Signal("excessive_subdomains", 25,
                        f"Excessive subdomain depth ({subdepth}) — common domain confusion tactic",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.70))
        elif subdepth == 3:
            emit(Signal("deep_subdomains", 12,
                        f"Unusually deep subdomain structure ({subdepth} levels)",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.50))

        # ── 14. DGA detection ─────────────────────────────────────────────────
        ascii_base = self._normalize_unicode(base)
        if self._is_dga(ascii_base):
            emit(Signal("dga_domain", 45,
                        "Domain base label matches DGA patterns — high entropy, unpronounceable",
                        ThreatCategory.DGA_DOMAIN, 0.75, ascii_base))
        elif entropy_val > 4.0:
            emit(Signal("high_entropy", 20,
                        f"High Shannon entropy on domain ({entropy_val:.2f}) — may be auto-generated",
                        ThreatCategory.DGA_DOMAIN, 0.60, f"{entropy_val:.2f}"))
        elif entropy_val > 3.5:
            emit(Signal("moderate_entropy", 8,
                        f"Moderate domain entropy ({entropy_val:.2f})",
                        ThreatCategory.DGA_DOMAIN, 0.40, f"{entropy_val:.2f}"))

        # ── 15. Credential keyword density ───────────────────────────────────
        cred_hits = [kw for kw in self.KEYWORDS_CREDENTIAL
                     if kw in full_text or kw in domain]
        if len(cred_hits) >= 3:
            emit(Signal("credential_keywords_high", 35,
                        f"High credential-keyword density ({len(cred_hits)}): {', '.join(cred_hits[:6])}",
                        ThreatCategory.CREDENTIAL_HARVESTING, 0.80,
                        ", ".join(cred_hits[:6])))
        elif len(cred_hits) == 2:
            emit(Signal("credential_keywords_medium", 20,
                        f"Credential-luring keywords detected: {', '.join(cred_hits)}",
                        ThreatCategory.CREDENTIAL_HARVESTING, 0.60,
                        ", ".join(cred_hits)))

        # ── 16. Malware delivery keywords ────────────────────────────────────
        mal_hits = [kw for kw in self.KEYWORDS_MALWARE if kw in full_text or kw in domain]
        if len(mal_hits) >= 2:
            emit(Signal("malware_keywords", 25,
                        f"Malware-delivery keywords detected: {', '.join(mal_hits)}",
                        ThreatCategory.MALWARE_DELIVERY, 0.65, ", ".join(mal_hits)))

        # ── 17. Malware file extension in path ────────────────────────────────
        for ext in self.MALWARE_EXTENSIONS:
            if path.endswith(ext):
                emit(Signal("malware_extension", 40,
                            f"Path ends with executable/dangerous extension '{ext}'",
                            ThreatCategory.MALWARE_DELIVERY, 0.80, ext))
                break

        # ── 18. Credential harvesting page name ───────────────────────────────
        path_stem = path.rstrip("/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if path_stem in self.HARVEST_PAGES:
            emit(Signal("harvest_page", 20,
                        f"Path resolves to known credential-harvesting page name: '{path_stem}'",
                        ThreatCategory.CREDENTIAL_HARVESTING, 0.55, path_stem))

        # ── 19. Brand impersonation in domain ─────────────────────────────────
        for brand in self._brand_names:
            official = self._brand_map[brand]
            if brand in domain and reg_dom != official:
                emit(Signal(f"brand_domain_{brand}", 45,
                            f"Brand '{brand}' present in domain but registrable domain "
                            f"'{reg_dom}' is not '{official}'",
                            ThreatCategory.BRAND_IMPERSONATION, 0.85, domain))

        # ── 20. Brand in path / query (without domain match) ─────────────────
        for brand in self._brand_names:
            official = self._brand_map[brand]
            if brand in full_text and brand not in domain and reg_dom != official:
                emit(Signal(f"brand_path_{brand}", 15,
                            f"Brand '{brand}' appears in URL path/query but not in domain",
                            ThreatCategory.BRAND_IMPERSONATION, 0.50, brand))
                break

        # ── 21. Typosquatting (3 independent normalisation methods) ──────────
        typo_base = self._normalize_typo(base)
        homo_base = self._apply_homoglyphs(base)

        for brand in self._brand_names:
            official = self._brand_map[brand]
            if reg_dom == official:
                continue
            best_sim = max(
                self._similarity(typo_base, brand),
                self._similarity(ascii_base, brand),
                self._similarity(homo_base, brand),
            )
            if best_sim >= 0.85:
                emit(Signal(f"typosquat_high_{brand}", 55,
                            f"Strong typosquatting — '{base}' closely resembles '{brand}' ({best_sim:.0%})",
                            ThreatCategory.TYPOSQUATTING, 0.90,
                            f"{base} ~ {brand} ({best_sim:.0%})"))
            elif best_sim >= 0.72:
                emit(Signal(f"typosquat_medium_{brand}", 30,
                            f"Moderate typosquatting — '{base}' partially resembles '{brand}' ({best_sim:.0%})",
                            ThreatCategory.TYPOSQUATTING, 0.70,
                            f"{base} ~ {brand} ({best_sim:.0%})"))

        # ── 22. Combo-squatting (brand + credential keyword in same domain) ───
        for brand in self._brand_names:
            official = self._brand_map[brand]
            if reg_dom == official:
                continue
            if brand in domain:
                overlap = [kw for kw in self.KEYWORDS_CREDENTIAL if kw in domain]
                if overlap:
                    emit(Signal(f"combosquat_{brand}", 50,
                                f"Combo-squatting: '{brand}' + credential keyword(s) "
                                f"'{', '.join(overlap[:3])}' combined in domain",
                                ThreatCategory.BRAND_IMPERSONATION, 0.88, domain))
                    break

        # ── 23. Brand-as-subdomain attack ──────────────────────────────────────
        # e.g. paypal.com.evil.xyz — official domain used as subdomain of attacker domain
        subdomain_part = domain[:-(len(reg_dom) + 1)] if domain.endswith("." + reg_dom) else ""
        if subdomain_part:
            for brand in self._brand_names:
                official = self._brand_map[brand]
                if official in subdomain_part or brand in subdomain_part:
                    emit(Signal(f"brand_as_subdomain_{brand}", 65,
                                f"'{official}' used as subdomain of attacker-controlled "
                                f"'{reg_dom}' — classic phishing trick",
                                ThreatCategory.BRAND_IMPERSONATION, 0.95, domain))
                    break

        # ── 24. Open redirect parameters ──────────────────────────────────────
        try:
            qs = parse_qs(query_str, keep_blank_values=True)
            redir_found = [p for p in qs if p in self.REDIRECT_PARAMS]
            if redir_found:
                emit(Signal("open_redirect_param", 25,
                            f"Open redirect parameter(s) in query string: {', '.join(redir_found)}",
                            ThreatCategory.OPEN_REDIRECT, 0.65, str(redir_found)))
        except Exception:
            pass

        # ── 25. Hyphen abuse ───────────────────────────────────────────────────
        hyphens = base.count("-")
        if hyphens >= 4:
            emit(Signal("hyphen_severe", 22,
                        f"Excessive hyphens ({hyphens}) in base label — hallmark of phishing domains",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.75))
        elif hyphens >= 2:
            emit(Signal("hyphen_moderate", 10,
                        f"Multiple hyphens ({hyphens}) in base label",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.45))

        # ── 26. Digit-heavy base label ─────────────────────────────────────────
        if base:
            digit_ratio = sum(c.isdigit() for c in base) / len(base)
            if digit_ratio > 0.5:
                emit(Signal("digit_heavy", 20,
                            f"Base label is {digit_ratio:.0%} digits — atypical for legitimate services",
                            ThreatCategory.SUSPICIOUS_STRUCTURE, 0.60, f"{digit_ratio:.0%}"))

        # ── 27. Base64 in query (exfiltration / obfuscated payload) ───────────
        b64_found = self._RE_B64.findall(query_str)
        if b64_found:
            emit(Signal("base64_in_query", 20,
                        "Long Base64-like string in query — possible data exfiltration or obfuscated payload",
                        ThreatCategory.DATA_EXFILTRATION, 0.55,
                        b64_found[0][:40] + "…"))

        # ── 28. data: URI embedded in query / fragment ─────────────────────────
        if "data:" in query_str or "data:" in fragment:
            emit(Signal("data_uri_embedded", 50,
                        "data: URI in query/fragment — XSS / redirect obfuscation technique",
                        ThreatCategory.OBFUSCATION, 0.85))

        # ── 29. IP-like segment in domain labels ────────────────────────────────
        for part in domain.split("."):
            if self._RE_IP.match(part):
                emit(Signal("ip_in_subdomain", 30,
                            f"IP-like segment '{part}' found in domain — evasion technique",
                            ThreatCategory.SUSPICIOUS_STRUCTURE, 0.80, part))
                break

        # ── 30. Bare / dotless domain ───────────────────────────────────────────
        if "." not in domain and not is_ip:
            emit(Signal("bare_domain", 12,
                        "Domain contains no dots — possible intranet abuse or obfuscation",
                        ThreatCategory.SUSPICIOUS_STRUCTURE, 0.40))

        # ── Final scoring ───────────────────────────────────────────────────────
        # Confidence-weighted sum, capped at 100
        raw_score   = sum(int(s.score * s.confidence) for s in signals)
        final_score = min(raw_score, 100)

        if final_score >= self.THRESHOLD_PHISHING:
            verdict = Verdict.PHISHING
        elif final_score >= self.THRESHOLD_SUSPICIOUS:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        reasons = [s.reason for s in signals] if signals else ["No significant threats detected"]
        t_ms    = (time.perf_counter() - t0) * 1000

        result = AnalysisResult(
            verdict=verdict,
            confidence=final_score,
            reasons=reasons,
            signals=signals,
            threat_categories=sorted(c.value for c in categories),
            domain=domain,
            tld=tld,
            is_ip=is_ip,
            is_idn=is_idn,
            subdomain_depth=subdepth,
            entropy=entropy_val,
            analysis_time_ms=t_ms,
            url_decoded=url_decoded,
        )

        logger.debug(
            "analyze url=%r verdict=%s score=%d signals=%d t_ms=%.2f",
            url, verdict.value, final_score, len(signals), t_ms,
        )

        return result.to_dict()


# Module-level singleton — drop-in replacement for existing import
detector = PhishingDetector()
