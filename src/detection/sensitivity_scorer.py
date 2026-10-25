"""
Layer 2: Dynamic Sensitivity Scoring Engine.
Calculates token sensitivity levels (0 to 3) combining AST context,
pattern entropy, and semantic classification.
Prevents over-masking so the LLM retains architectural comprehension.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from .ast_parser import ASTCodeParser
from .pattern_matcher import SecretPatternMatcher
from .ner_engine import LocalNEREngine


@dataclass
class EntityMatch:
    value: str
    category: str
    sensitivity_score: int  # 0: None, 1: Low, 2: Medium, 3: Critical
    confidence: float
    span: Optional[tuple] = None
    context_hint: str = ""
    assigned_placeholder: Optional[str] = None


class DynamicSensitivityScorer:
    """
    Evaluates tokens and assigns risk scores.
    Score 3 (Critical): Raw credentials, API keys, private keys, passwords.
    Score 2 (Medium): Corporate PII, database hosts, internal IPs, auth headers.
    Score 1 (Low): Internal module names, function identifiers.
    Score 0 (Safe): Generic variables (i, loop counters, standard libraries).
    """

    SAFE_IDENTIFIERS = {
        "i", "j", "k", "n", "x", "y", "z", "idx", "index", "count", "total",
        "data", "df", "res", "resp", "response", "req", "request", "item", "val",
        "value", "key", "result", "status", "msg", "message", "error", "err",
        "app", "client", "server", "config", "session", "user_id", "id", "uid"
    }

    SQL_KEYWORDS = {"select", "insert", "update", "delete", "from", "where", "table", "join", "order by"}

    def __init__(self, min_mask_threshold: int = 2):
        self.ast_parser = ASTCodeParser()
        self.pattern_matcher = SecretPatternMatcher()
        self.ner_engine = LocalNEREngine()
        self.min_mask_threshold = min_mask_threshold

    def analyze(self, code: str) -> List[EntityMatch]:
        """
        Runs unified analysis across AST, patterns, and NER,
        merging overlapping spans and determining the sensitivity level.
        """
        matches_dict: Dict[str, EntityMatch] = {}

        # 1. AST Analysis
        ast_results = self.ast_parser.parse_python(code)
        for item in ast_results:
            val = item["value"]
            if not isinstance(val, str) or len(val.strip()) < 3:
                continue

            # Skip safe variables
            stripped_val = val.strip()
            if stripped_val in self.SAFE_IDENTIFIERS and not item.get("is_suspicious_name"):
                continue

            # Skip SQL queries and code fragments from being labeled as secrets
            if any(k in stripped_val.lower() for k in self.SQL_KEYWORDS) and " " in stripped_val:
                continue

            score = 1
            cat = "CODE_IDENTIFIER"
            if item.get("is_suspicious_name"):
                score = 3
                cat = "CREDENTIAL_ASSIGNMENT"
            elif item["type"] == "ast_env_call":
                score = 2
                cat = "ENV_VARIABLE"

            # Secrets, API keys, and hashes NEVER contain whitespace
            if " " not in val and len(val) >= 12:
                entropy = self.pattern_matcher.calculate_shannon_entropy(val)
                if entropy > 3.8:
                    score = 3
                    cat = "HIGH_ENTROPY_KEY"

            self._record_match(matches_dict, val, cat, score, 0.90, item.get("context", "AST Node"))

        # 2. Secret Pattern Scanning
        pattern_results = self.pattern_matcher.scan_text(code)
        for item in pattern_results:
            val = item["value"]
            cat = item["rule"]
            score = 3  # All regex rules for secrets are critical
            self._record_match(matches_dict, val, cat, score, item["confidence"], f"Pattern rule: {cat}")

        # 3. Local NER Scanning
        ner_results = self.ner_engine.scan_pii(code)
        for item in ner_results:
            val = item["value"]
            cat = item["category"]
            score = 3 if cat in ("FINANCIAL_IDENTIFIER", "IP_ADDRESS_V6") else 2
            self._record_match(matches_dict, val, cat, score, item["confidence"], f"NER category: {cat}")

        # Filter out entities below minimum masking threshold
        filtered = [
            entity for entity in matches_dict.values()
            if entity.sensitivity_score >= self.min_mask_threshold
        ]

        # Sort from longest string to shortest to prevent partial substring collisions
        filtered.sort(key=lambda x: len(x.value), reverse=True)
        return filtered

    def _record_match(self, store: Dict[str, EntityMatch], value: str, category: str,
                      score: int, confidence: float, hint: str):
        if value in store:
            if score > store[value].sensitivity_score:
                store[value].sensitivity_score = score
                store[value].category = category
            store[value].confidence = max(store[value].confidence, confidence)
        else:
            store[value] = EntityMatch(
                value=value,
                category=category,
                sensitivity_score=score,
                confidence=confidence,
                context_hint=hint
            )
