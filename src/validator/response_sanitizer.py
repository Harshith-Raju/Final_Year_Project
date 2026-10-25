"""
Layer 6 - Subsystem C: Output Validator & Sanitizer Orchestrator.
Combines secret scanning and integrity validation to provide certified output safety.
"""

from typing import Dict, Any, Set
from .secret_scanner import OutputSecretScanner
from .placeholder_integrity import PlaceholderIntegrityChecker


class OutputValidator:
    """
    Certified Output Validation Layer.
    """

    def __init__(self):
        self.secret_scanner = OutputSecretScanner()
        self.integrity_checker = PlaceholderIntegrityChecker()

    def validate_and_sanitize(
        self,
        raw_response: str,
        registered_secrets: Set[str],
        valid_placeholders: Set[str]
    ) -> Dict[str, Any]:
        """
        Runs comprehensive safety checks and scrubs any accidental leaks before local de-anonymization.
        """
        leak_report = self.secret_scanner.check_for_leaks(raw_response, registered_secrets)
        integrity_report = self.integrity_checker.verify_placeholders(raw_response, valid_placeholders)

        sanitized_text = raw_response

        # If any registered secret was accidentally echoed, redact it immediately
        if not leak_report["is_safe"]:
            for secret in registered_secrets:
                if secret in sanitized_text:
                    sanitized_text = sanitized_text.replace(secret, "[REDACTED_LEAK_PREVENTED]")

        overall_valid = leak_report["is_safe"] and integrity_report["integrity_passed"]

        return {
            "is_valid": overall_valid,
            "leak_check": leak_report,
            "integrity_check": integrity_report,
            "sanitized_response": sanitized_text,
            "leakage_rate": 0.0 if leak_report["is_safe"] else 1.0,
        }
