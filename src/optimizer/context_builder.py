"""
Layer 4 - Subsystem C: Context Builder.
Constructs the final token-optimized prompt payload including sanitized code,
retrieved CWE security standards, and structured evaluation guidelines.
"""

from typing import List, Dict, Any
from .token_compressor import TokenCompressor
from .rag_knowledge_base import SecurityRAGKnowledgeBase


class ContextBuilder:
    """
    Synthesizes sanitized code and RAG context into an optimal prompt.
    """

    def __init__(self):
        self.compressor = TokenCompressor()
        self.rag = SecurityRAGKnowledgeBase()

    def build_prompt(
        self,
        sanitized_code: str,
        user_intent: str = "Perform a thorough security vulnerability and code quality review",
        top_k_rag: int = 3
    ) -> Dict[str, Any]:
        """
        Builds the prompt and measures token metrics.
        """
        # 1. Compress code to save token budget
        optimized_code, comp_stats = self.compressor.compress_code(sanitized_code)

        # 2. Retrieve relevant security context via RAG
        rag_rules = self.rag.retrieve(optimized_code, top_k=top_k_rag)

        # 3. Format RAG rules into concise reference string
        rag_text = ""
        if rag_rules:
            rag_text = "### RELEVANT SECURITY STANDARDS (RAG RETRIEVAL):\n"
            for r in rag_rules:
                rag_text += f"- [{r['id']}] {r['title']} ({r['owasp']})\n  Focus: {r['description']}\n  Remediation: {r['remediation']}\n\n"

        system_instruction = (
            "You are an expert Application Security and Code Quality Reviewer.\n"
            "Analyze the submitted code for vulnerabilities, logic bugs, insecure configurations, and architectural issues.\n"
            "NOTE ON PRIVACY: Sensitive data (credentials, keys, PII) has been securely masked with placeholders (e.g., __API_KEY_1__, __USER_EMAIL_1__).\n"
            "Treat these placeholders as valid abstract values. DO NOT attempt to guess, extract, or hallucinate real secrets.\n"
            "Format your response with:\n"
            "1. Summary of Security Posture\n"
            "2. Identified Vulnerabilities (with CWE IDs and severity: High/Medium/Low)\n"
            "3. Secure Code Recommendations (using the same placeholders)\n"
            "4. Overall Quality Rating (1-10)\n"
        )

        user_content = (
            f"Developer Request: {user_intent}\n\n"
            f"{rag_text}"
            f"### CODE TO REVIEW:\n```python\n{optimized_code}\n```"
        )

        full_prompt_text = system_instruction + "\n" + user_content
        prompt_tokens = self.compressor.estimate_tokens(full_prompt_text)

        return {
            "system_instruction": system_instruction,
            "user_content": user_content,
            "full_prompt": full_prompt_text,
            "rag_rules": rag_rules,
            "compression_stats": comp_stats,
            "estimated_prompt_tokens": prompt_tokens,
            "optimized_code": optimized_code,
        }
