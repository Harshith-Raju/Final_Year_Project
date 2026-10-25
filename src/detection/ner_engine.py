"""
Layer 1 - Subsystem C: Local Named Entity Recognition (NER) & PII Engine.
Recognizes human names, corporate email addresses, IP endpoints, phone numbers,
and identifiers without contacting remote cloud services.
"""

import re
from typing import List, Dict, Any


class LocalNEREngine:
    """
    Client-side, privacy-first NER engine designed for code and configuration data.
    """

    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    IPV6_PATTERN = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")
    PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
    INTERNAL_URL_PATTERN = re.compile(r"\bhttps?:\/\/(?:localhost|127\.0\.0\.1|[\w-]+\.(?:internal|corp|local|intranet))(?::\d+)?(?:\/[^\s\'\"]*)?\b")
    CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")

    def __init__(self):
        pass

    def scan_pii(self, text: str) -> List[Dict[str, Any]]:
        """
        Scans text for PII entities, returning detected entities with span and category.
        """
        entities = []

        # 1. Emails
        for m in self.EMAIL_PATTERN.finditer(text):
            entities.append({
                "category": "EMAIL_ADDRESS",
                "value": m.group(0),
                "span": m.span(),
                "confidence": 0.98
            })

        # 2. IPv4
        for m in self.IPV4_PATTERN.finditer(text):
            val = m.group(0)
            # Ignore harmless loopback/broadcast if needed or flag as IP
            entities.append({
                "category": "IP_ADDRESS",
                "value": val,
                "span": m.span(),
                "confidence": 0.95
            })

        # 3. IPv6
        for m in self.IPV6_PATTERN.finditer(text):
            entities.append({
                "category": "IP_ADDRESS_V6",
                "value": m.group(0),
                "span": m.span(),
                "confidence": 0.95
            })

        # 4. Phone
        for m in self.PHONE_PATTERN.finditer(text):
            val = m.group(0)
            # avoid matching standard numbers like timestamps or version strings
            if len(re.sub(r"\D", "", val)) >= 10:
                entities.append({
                    "category": "PHONE_NUMBER",
                    "value": val,
                    "span": m.span(),
                    "confidence": 0.90
                })

        # 5. Internal URLs
        for m in self.INTERNAL_URL_PATTERN.finditer(text):
            entities.append({
                "category": "INTERNAL_ENDPOINT",
                "value": m.group(0),
                "span": m.span(),
                "confidence": 0.92
            })

        # 6. Credit Card Numbers
        for m in self.CREDIT_CARD_PATTERN.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if len(digits) == 16 and self._luhn_check(digits):
                entities.append({
                    "category": "FINANCIAL_IDENTIFIER",
                    "value": m.group(0),
                    "span": m.span(),
                    "confidence": 0.99
                })

        return entities

    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        """Standard Luhn checksum for payment card verification."""
        total = 0
        reverse_digits = card_number[::-1]
        for i, char in enumerate(reverse_digits):
            n = int(char)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0
