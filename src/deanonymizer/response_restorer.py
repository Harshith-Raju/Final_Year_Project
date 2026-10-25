"""
Layer 7 - Subsystem A: Local Response Restorer.
Operates exclusively on the local client to restore semantic placeholders
back to their original variable names or values in the final developer view.
"""

from typing import Dict, Any
from ..vault.vault_manager import PseudonymizationVault


class LocalResponseRestorer:
    """
    De-anonymizes LLM review reports on the local side.
    """

    def __init__(self, vault: PseudonymizationVault):
        self.vault = vault

    def restore_response(self, validated_response: str) -> str:
        """
        Replaces placeholders with original local values.
        """
        return self.vault.restore_text(validated_response)
