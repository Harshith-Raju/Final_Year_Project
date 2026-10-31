"""
Layer 1 - Subsystem B: Pattern Matcher & Shannon Entropy Calculator.
Specialized in cryptographic token detection, cloud credentials, high-entropy secrets,
and structured sensitive indicators.
"""

import math
import re
from typing import List, Dict, Any


class SecretPatternMatcher:
    """
    Regex + Shannon Entropy detection engine for cryptographic keys,
    passwords, database URLs, and connection secrets.
    """

    PATTERNS: Dict[str, re.Pattern] = {
        "OPENAI_API_KEY": re.compile(r"\bsk-[a-zA-Z0-9_-]{20,64}\b"),
        "GITHUB_TOKEN": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}\b"),
        "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS_SECRET_KEY": re.compile(r"""(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([0-9a-zA-Z/+]{40})["']?"""),
        "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z\\-_]{35}\b"),
        "SLACK_TOKEN": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
        "STRIPE_KEY": re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34}\b"),
        "JWT_TOKEN": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "DATABASE_URL": re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|sqlite|mssql):\/\/[^\s\'\"]+:[^\s\'\"]+@[^\s\'\"]+\b",
            re.IGNORECASE
        ),
        "PRIVATE_KEY_HEADER": re.compile(
            r"-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----"
        ),
        "BEARER_TOKEN": re.compile(r"Bearer\s+([A-Za-z0-9\-_\.~+/=]{20,})", re.IGNORECASE),
        "GENERIC_SECRET_IN_STRING": re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|api_key|token|auth_token|client_secret)\s*[:=]\s*["']([^"']{6,})["']"""
        ),
    }

    def __init__(self, entropy_threshold: float = 3.6):
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """
        Calculates Shannon Entropy (bits per character) of a string.
        High entropy (> 3.5 - 4.0) usually indicates encrypted, hashed, or random keys.
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p_x = count / length
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return round(entropy, 3)

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Scans code/text against structured regex rules and flags high-entropy sequences.
        """
        matches = []
        seen_spans = set()

        # 1. Regex rule scans
        for rule_name, pattern in self.PATTERNS.items():
            for m in pattern.finditer(text):
                # If pattern has a capturing group (e.g. for key/token value inside quotes), use group 1
                if m.lastindex and m.lastindex >= 1 and rule_name == "GENERIC_SECRET_IN_STRING":
                    val = m.group(1)
                    span = m.span(1)
                else:
                    val = m.group(0)
                    span = m.span()
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                entropy = self.calculate_shannon_entropy(val)
                matches.append({
                    "type": "regex_rule",
                    "rule": rule_name,
                    "value": val,
                    "span": span,
                    "entropy": entropy,
                    "confidence": 0.95
                })

        # 2. Free-token entropy scan for candidate strings
        # Splits code into alphanumeric words/tokens to catch obscure keys
        candidate_words = re.findall(r'[a-zA-Z0-9_\-\.]{16,}', text)
        for word in candidate_words:
            # Skip if common camelCase, standard identifiers or plain English-like variable
            if word.lower() in ("implementation", "unsupportedmediatype", "authentication", "financial_records", "fetch_financial_records", "dispatch_cloud_job"):
                continue
            # If it's a standard function or identifier name without secret keywords, skip
            if word.isidentifier() and not any(s in word.lower() for s in ("key", "secret", "token", "pass", "pwd", "auth")):
                continue
            entropy = self.calculate_shannon_entropy(word)
            if entropy >= self.entropy_threshold:
                # Find span
                start_idx = text.find(word)
                if start_idx != -1:
                    span = (start_idx, start_idx + len(word))
                    if span not in seen_spans:
                        seen_spans.add(span)
                        matches.append({
                            "type": "high_entropy_secret",
                            "rule": "SHANNON_ENTROPY",
                            "value": word,
                            "span": span,
                            "entropy": entropy,
                            "confidence": 0.85
                        })

        return matches
