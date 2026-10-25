"""
Layer 6 - Subsystem B: Placeholder Integrity Checker.
Verifies that semantic placeholders (e.g. __API_KEY_1__) passed to the model
remain intact, syntactically well-formed, and correctly referenced in code remedies.
"""

import re
from typing import List, Dict, Any, Set


class PlaceholderIntegrityChecker:
    """
    Validates that placeholders used in LLM response correspond to valid vault aliases.
    """

    PLACEHOLDER_REGEX = re.compile(r"__[A-Z_]+_\d+__")

    def verify_placeholders(self, response_text: str, valid_placeholders: Set[str]) -> Dict[str, Any]:
        found_in_response = set(self.PLACEHOLDER_REGEX.findall(response_text))

        # Check for unknown or corrupted placeholder tokens
        hallucinated = found_in_response - valid_placeholders
        properly_referenced = found_in_response.intersection(valid_placeholders)

        return {
            "valid_placeholders_sent": list(valid_placeholders),
            "placeholders_referenced_in_response": list(properly_referenced),
            "unknown_placeholders_detected": list(hallucinated),
            "integrity_passed": len(hallucinated) == 0,
        }
