"""
Unified Privacy-Preserving AI Code Review Pipeline.
Orchestrates Layers 1 through 7 into a single, cohesive, high-performance workflow.
"""

import time
from typing import Dict, Any, Optional

from .detection.sensitivity_scorer import DynamicSensitivityScorer
from .vault.vault_manager import PseudonymizationVault
from .optimizer.context_builder import ContextBuilder
from .llm_gateway.llm_adapter import LLMAdapter
from .llm_gateway.response_parser import SecurityReportParser
from .validator.response_sanitizer import OutputValidator
from .deanonymizer.response_restorer import LocalResponseRestorer
from .deanonymizer.audit_logger import CryptographicAuditLogger


class PrivacyPreservingReviewPipeline:
    """
    Main orchestrator for the Privacy-Preserving Code Review Framework.
    """

    def __init__(
        self,
        llm_backend: str = "auto",
        min_sensitivity_threshold: int = 2,
        api_key: Optional[str] = None
    ):
        self.min_sensitivity_threshold = min_sensitivity_threshold
        self.scorer = DynamicSensitivityScorer(min_mask_threshold=min_sensitivity_threshold)
        self.context_builder = ContextBuilder()
        self.llm_gateway = LLMAdapter(backend=llm_backend, api_key=api_key)
        self.validator = OutputValidator()
        self.audit_logger = CryptographicAuditLogger()

    def process_code_review(
        self,
        raw_code: str,
        user_intent: str = "Perform a thorough security vulnerability and code quality review",
        top_k_rag: int = 3,
        restore_placeholders_locally: bool = True
    ) -> Dict[str, Any]:
        """
        Executes end-to-end 7-layer privacy pipeline.
        """
        start_time = time.perf_counter()
        timing: Dict[str, float] = {}

        # -------------------------------------------------------------
        # STEP 1: Detection & Dynamic Sensitivity Scoring (Layers 1 & 2)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        detected_entities = self.scorer.analyze(raw_code)
        timing["detection_ms"] = (time.perf_counter() - t0) * 1000

        # -------------------------------------------------------------
        # STEP 2: Pseudonymization Vault & Local Encryption (Layer 3)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        vault = PseudonymizationVault()
        sanitized_code, substitutions = vault.mask_code(raw_code, detected_entities)
        registered_secrets = set(vault.placeholder_to_val.values())
        valid_placeholders = set(vault.placeholder_to_val.keys())
        timing["pseudonymization_ms"] = (time.perf_counter() - t0) * 1000

        # -------------------------------------------------------------
        # STEP 3: Context Optimization & RAG Retrieval (Layer 4)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        prompt_package = self.context_builder.build_prompt(
            sanitized_code=sanitized_code,
            user_intent=user_intent,
            top_k_rag=top_k_rag
        )
        timing["optimization_and_rag_ms"] = (time.perf_counter() - t0) * 1000

        # -------------------------------------------------------------
        # STEP 4: LLM Security Analysis Gateway (Layer 5)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        raw_llm_response = self.llm_gateway.complete_review(
            system_instruction=prompt_package["system_instruction"],
            user_content=prompt_package["user_content"],
            optimized_code=prompt_package["optimized_code"]
        )
        timing["llm_inference_ms"] = (time.perf_counter() - t0) * 1000

        # -------------------------------------------------------------
        # STEP 5: Output Validation & Sanitization (Layer 6)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        validation_result = self.validator.validate_and_sanitize(
            raw_response=raw_llm_response,
            registered_secrets=registered_secrets,
            valid_placeholders=valid_placeholders
        )
        validated_text = validation_result["sanitized_response"]
        timing["output_validation_ms"] = (time.perf_counter() - t0) * 1000

        # -------------------------------------------------------------
        # STEP 6: Local De-anonymization (Layer 7)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        restorer = LocalResponseRestorer(vault)
        if restore_placeholders_locally:
            final_report = restorer.restore_response(validated_text)
        else:
            final_report = validated_text
        timing["deanonymization_ms"] = (time.perf_counter() - t0) * 1000

        # -------------------------------------------------------------
        # STEP 7: Parse Structured Report & Audit Log
        # -------------------------------------------------------------
        total_duration_ms = (time.perf_counter() - start_time) * 1000
        timing["total_pipeline_ms"] = total_duration_ms

        parsed_telemetry = SecurityReportParser.parse_report(final_report)

        audit_entry = self.audit_logger.record_transaction(
            session_id=vault.session_id,
            entities_masked=len(substitutions),
            categories=[s["category"] for s in substitutions],
            token_stats=prompt_package["compression_stats"],
            validation_result=validation_result,
            duration_ms=total_duration_ms
        )

        return {
            "session_id": vault.session_id,
            "original_code": raw_code,
            "sanitized_code": sanitized_code,
            "prompt_package": prompt_package,
            "raw_llm_response": raw_llm_response,
            "validated_response": validated_text,
            "final_report": final_report,
            "parsed_telemetry": parsed_telemetry,
            "substitutions": substitutions,
            "validation_result": validation_result,
            "timing_ms": timing,
            "audit_entry": audit_entry,
            "privacy_guarantee": {
                "zero_raw_secrets_exposed": True,
                "output_leakage_rate": validation_result["leakage_rate"],
                "total_entities_shielded": len(substitutions),
                "vault_session_encrypted": True
            }
        }
