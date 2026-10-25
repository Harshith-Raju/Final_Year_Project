"""
Automated Test Suite for Privacy-Preserving AI Code Review Framework.
Verifies all 7 layers, cryptographic guarantees, reversibility, and zero-egress leakage.
"""

import sys
import os

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.detection.ast_parser import ASTCodeParser
from src.detection.pattern_matcher import SecretPatternMatcher
from src.detection.ner_engine import LocalNEREngine
from src.detection.sensitivity_scorer import DynamicSensitivityScorer
from src.vault.crypto_engine import CryptoEngine
from src.vault.vault_manager import PseudonymizationVault
from src.optimizer.token_compressor import TokenCompressor
from src.optimizer.rag_knowledge_base import SecurityRAGKnowledgeBase
from src.validator.response_sanitizer import OutputValidator
from src.pipeline import PrivacyPreservingReviewPipeline


def test_ast_parser():
    code = 'api_key = "sk-live-1234567890abcdef"\nx = 10\n'
    parser = ASTCodeParser()
    results = parser.parse_python(code)
    assert len(results) > 0
    suspicious = [r for r in results if r.get("is_suspicious_name")]
    assert len(suspicious) >= 1
    assert suspicious[0]["var_name"] == "api_key"
    print("[PASS] test_ast_parser passed")


def test_pattern_and_entropy():
    matcher = SecretPatternMatcher()
    sample_key = "sk-abcdef1234567890abcdef1234567890"
    matches = matcher.scan_text(f'OPENAI = "{sample_key}"')
    assert len(matches) > 0
    assert matches[0]["rule"] == "OPENAI_API_KEY"

    # Entropy of high-entropy key should be high
    entropy = matcher.calculate_shannon_entropy("7x9bQ2!mK#91vL$0")
    assert entropy > 3.2
    print("[PASS] test_pattern_and_entropy passed")


def test_ner_engine():
    ner = LocalNEREngine()
    text = "Contact support at security@srkrec.edu.in or server 192.168.1.50"
    matches = ner.scan_pii(text)
    categories = [m["category"] for m in matches]
    assert "EMAIL_ADDRESS" in categories
    assert "IP_ADDRESS" in categories
    print("[PASS] test_ner_engine passed")


def test_sensitivity_scorer():
    scorer = DynamicSensitivityScorer(min_mask_threshold=2)
    code = '''
api_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
user_email = "test@srkrec.edu.in"
i = 0
for i in range(10):
    pass
'''
    entities = scorer.analyze(code)
    values = [e.value for e in entities]
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB" in values
    assert "test@srkrec.edu.in" in values
    # Loop variable 'i' should NOT be masked
    assert "i" not in values
    print("[PASS] test_sensitivity_scorer passed")


def test_crypto_engine_encryption_decryption():
    crypto = CryptoEngine()
    test_dict = {"API_KEY": "sk-test-123", "PORT": 8080}
    encrypted = crypto.encrypt_mapping(test_dict)
    assert isinstance(encrypted, str)
    assert encrypted != str(test_dict)

    decrypted = crypto.decrypt_mapping(encrypted)
    assert decrypted == test_dict
    print("[PASS] test_crypto_engine_encryption_decryption passed")


def test_vault_reversibility():
    scorer = DynamicSensitivityScorer(min_mask_threshold=2)
    code = 'secret_key = "sk-proj-supersecretkey123456"\nprint("connecting")'
    entities = scorer.analyze(code)

    vault = PseudonymizationVault()
    sanitized, substitutions = vault.mask_code(code, entities)

    # Raw secret must NOT be in sanitized code
    assert "sk-proj-supersecretkey123456" not in sanitized
    assert "__" in sanitized  # Contains placeholder

    # Restoring text must return the original secret
    restored = vault.restore_text(sanitized)
    assert restored == code
    print("[PASS] test_vault_reversibility passed")


def test_token_compressor_and_rag():
    compressor = TokenCompressor()
    code = '''
# ------------------------------------
# Main execution function
# ------------------------------------


def run():


    x = 1
    return x
'''
    compressed, stats = compressor.compress_code(code)
    assert stats["savings_percent"] > 0
    assert stats["optimized_tokens"] < stats["original_tokens"]

    rag = SecurityRAGKnowledgeBase()
    query = "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
    results = rag.retrieve(query, top_k=2)
    assert len(results) > 0
    top_cwe = results[0]["id"]
    assert top_cwe in ("CWE-89", "CWE-798")
    print("[PASS] test_token_compressor_and_rag passed")


def test_output_validator_zero_leakage():
    validator = OutputValidator()
    raw_response = "We reviewed the code with placeholder __API_KEY_1__ and recommend os.getenv."
    registered_secrets = {"super_secret_password_123"}
    valid_placeholders = {"__API_KEY_1__"}

    result = validator.validate_and_sanitize(raw_response, registered_secrets, valid_placeholders)
    assert result["is_valid"] is True
    assert result["leakage_rate"] == 0.0

    # Test detection of an accidental leak
    leaky_response = "The password super_secret_password_123 was insecure."
    leak_result = validator.validate_and_sanitize(leaky_response, registered_secrets, valid_placeholders)
    assert leak_result["leak_check"]["is_safe"] is False
    assert "[REDACTED_LEAK_PREVENTED]" in leak_result["sanitized_response"]
    print("[PASS] test_output_validator_zero_leakage passed")


def test_end_to_end_pipeline():
    pipeline = PrivacyPreservingReviewPipeline(llm_backend="mock")
    test_code = '''
import psycopg2

DB_PASS = "SuperSecretDbPassword2026!"
AWS_KEY = "AKIA1234567890ABCDEF"

def get_user(uid):
    conn = psycopg2.connect(f"postgresql://user:{DB_PASS}@10.0.0.1:5432/app")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return cursor.fetchall()
'''
    result = pipeline.process_code_review(test_code)

    assert result["privacy_guarantee"]["zero_raw_secrets_exposed"] is True
    assert result["privacy_guarantee"]["output_leakage_rate"] == 0.0
    assert len(result["substitutions"]) >= 2
    assert "SuperSecretDbPassword2026!" not in result["sanitized_code"]
    assert result["parsed_telemetry"]["vulnerabilities_count"] > 0
    print("[PASS] test_end_to_end_pipeline passed")


if __name__ == "__main__":
    print("=" * 60)
    print("Running Full Verification Test Suite...")
    print("=" * 60)
    test_ast_parser()
    test_pattern_and_entropy()
    test_ner_engine()
    test_sensitivity_scorer()
    test_crypto_engine_encryption_decryption()
    test_vault_reversibility()
    test_token_compressor_and_rag()
    test_output_validator_zero_leakage()
    test_end_to_end_pipeline()
    print("=" * 60)
    print("ALL TESTS PASSED WITH ZERO ERRORS (9/9)!")
    print("=" * 60)
