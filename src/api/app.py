"""
FastAPI REST API Service for Privacy-Preserving AI Code Review Framework.
Enables enterprise microservice integration, IDE plugins, and CI/CD pipeline automation.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from src.pipeline import PrivacyPreservingReviewPipeline
from src.optimizer.rag_knowledge_base import SecurityRAGKnowledgeBase

app = FastAPI(
    title="Privacy-Preserving AI Code Review API",
    description="Context-Aware, Token-Efficient LLM Gateway for Secure Code Reviews with Zero-Egress Secrets Protection.",
    version="1.0.0"
)

# Global in-memory pipeline instance
pipeline = PrivacyPreservingReviewPipeline(llm_backend="auto")
rag_kb = SecurityRAGKnowledgeBase()


class CodeReviewRequest(BaseModel):
    code: str = Field(..., description="Raw source code to review")
    intent: Optional[str] = Field("Perform comprehensive security and code quality review", description="Developer review prompt")
    sensitivity_threshold: Optional[int] = Field(2, ge=1, le=3, description="Minimum sensitivity score to mask (1-3)")
    restore_locally: Optional[bool] = Field(True, description="Whether to restore variable names in output locally")
    backend: Optional[str] = Field("auto", description="LLM backend: auto, mock, gemini, openai, or ollama")
    api_key: Optional[str] = Field(None, description="Optional API key for frontier LLMs")


class AnonymizeRequest(BaseModel):
    code: str = Field(..., description="Source code containing sensitive identifiers")
    sensitivity_threshold: Optional[int] = Field(2, ge=1, le=3)


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "online",
        "service": "Privacy-Preserving AI Code Review Gateway",
        "version": "1.0.0",
        "institution": "Dept. of CSE, SRKREC"
    }


@app.get("/api/v1/rules")
def get_security_rules():
    """Returns the list of indexed OWASP / CWE security guidelines available in the RAG module."""
    return {"total_rules": len(rag_kb.KNOWLEDGE_CORPUS), "rules": rag_kb.KNOWLEDGE_CORPUS}


@app.post("/api/v1/review")
def review_code(req: CodeReviewRequest):
    """
    Submits code to the 7-layer privacy-preserving code review pipeline.
    Ensures zero sensitive credentials leave the gateway.
    """
    try:
        custom_pipeline = PrivacyPreservingReviewPipeline(
            llm_backend=req.backend,
            min_sensitivity_threshold=req.sensitivity_threshold,
            api_key=req.api_key
        )
        result = custom_pipeline.process_code_review(
            raw_code=req.code,
            user_intent=req.intent,
            restore_placeholders_locally=req.restore_locally
        )
        return {
            "session_id": result["session_id"],
            "privacy_guarantee": result["privacy_guarantee"],
            "timing_ms": result["timing_ms"],
            "token_compression": result["prompt_package"]["compression_stats"],
            "retrieved_cwe_rules": [r["id"] for r in result["prompt_package"]["rag_rules"]],
            "final_report": result["final_report"],
            "substitutions_count": len(result["substitutions"]),
            "audit_hash": result["audit_entry"]["integrity_hash"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/anonymize")
def anonymize_code(req: AnonymizeRequest):
    """
    Anonymizes code without running full LLM evaluation.
    Useful for client-side pre-flight checks.
    """
    try:
        from src.detection.sensitivity_scorer import DynamicSensitivityScorer
        from src.vault.vault_manager import PseudonymizationVault

        scorer = DynamicSensitivityScorer(min_mask_threshold=req.sensitivity_threshold)
        entities = scorer.analyze(req.code)
        vault = PseudonymizationVault()
        sanitized_code, substitutions = vault.mask_code(req.code, entities)

        return {
            "session_id": vault.session_id,
            "sanitized_code": sanitized_code,
            "entities_masked": len(substitutions),
            "substitutions": substitutions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
