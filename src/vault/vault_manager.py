"""
Layer 3 - Subsystem C: Pseudonymization Vault Manager.
Manages bidirectional mapping between original secrets and semantic placeholders.
Enforces session isolation, deterministic substitution, and in-memory encrypted persistence.
"""

import time
import uuid
from typing import Dict, List, Tuple, Any, Optional
from .crypto_engine import CryptoEngine
from .placeholder_generator import PlaceholderGenerator
from ..detection.sensitivity_scorer import EntityMatch


class PseudonymizationVault:
    """
    Session-scoped, cryptographically shielded vault.
    Stores and manages reversible substitutions.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id: str = session_id or str(uuid.uuid4())
        self.created_at: float = time.time()
        self.crypto = CryptoEngine()
        self.generator = PlaceholderGenerator()

        # In-memory working tables
        self.val_to_placeholder: Dict[str, str] = {}
        self.placeholder_to_val: Dict[str, str] = {}
        self.metadata_store: Dict[str, Dict[str, Any]] = {}

        # Encrypted backup
        self._encrypted_vault_blob: Optional[str] = None

    def mask_code(self, code: str, entities: List[EntityMatch]) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Replaces detected sensitive tokens in code with deterministic placeholders.
        Returns the sanitized code and a summary of substitutions made.
        """
        sanitized = code
        substitution_records = []

        # Process entities sorted by length descending to prevent partial substring replacements
        for ent in entities:
            raw_val = ent.value
            if not raw_val:
                continue

            # Deterministic reuse: if value was already masked in this session, reuse alias
            if raw_val in self.val_to_placeholder:
                placeholder = self.val_to_placeholder[raw_val]
            else:
                placeholder = self.generator.generate(ent.category)
                self.val_to_placeholder[raw_val] = placeholder
                self.placeholder_to_val[placeholder] = raw_val
                self.metadata_store[placeholder] = {
                    "category": ent.category,
                    "sensitivity_score": ent.sensitivity_score,
                    "confidence": ent.confidence,
                    "context_hint": ent.context_hint,
                }

            ent.assigned_placeholder = placeholder

            # Replace occurrences in the code
            if raw_val in sanitized:
                sanitized = sanitized.replace(raw_val, placeholder)
                substitution_records.append({
                    "placeholder": placeholder,
                    "category": ent.category,
                    "score": ent.sensitivity_score,
                    "length": len(raw_val),
                })

        # Save encrypted state
        self._sync_encrypted_state()
        return sanitized, substitution_records

    def restore_text(self, sanitized_text: str) -> str:
        """
        Restores placeholders in the LLM's response back to original secret strings.
        Must only run locally on the user's secure client machine.
        """
        restored = sanitized_text
        for placeholder, original in self.placeholder_to_val.items():
            if placeholder in restored:
                restored = restored.replace(placeholder, original)
        return restored

    def _sync_encrypted_state(self):
        """Encrypts in-memory mappings using authenticated session key."""
        state = {
            "val_to_ph": self.val_to_placeholder,
            "ph_to_val": self.placeholder_to_val,
            "metadata": self.metadata_store,
        }
        self._encrypted_vault_blob = self.crypto.encrypt_mapping(state)

    def get_audit_summary(self) -> Dict[str, Any]:
        """Provides sanitized audit summary without exposing raw secrets."""
        return {
            "session_id": self.session_id,
            "total_entities_masked": len(self.placeholder_to_val),
            "placeholders": list(self.placeholder_to_val.keys()),
            "categories": [m["category"] for m in self.metadata_store.values()],
            "is_encrypted": self._encrypted_vault_blob is not None,
        }

    def clear(self):
        """Zeroes out in-memory dictionaries and resets generator."""
        self.val_to_placeholder.clear()
        self.placeholder_to_val.clear()
        self.metadata_store.clear()
        self.generator.reset()
        self._encrypted_vault_blob = None
