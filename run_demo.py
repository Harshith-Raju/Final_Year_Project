"""
Standalone Demonstration Runner for Privacy-Preserving AI Code Review Framework.
Executes an end-to-end security audit and prints formatted step-by-step pipeline telemetry.
"""

import sys
import os

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.pipeline import PrivacyPreservingReviewPipeline

DEMO_CODE = '''import os
import psycopg2
import requests

# Hardcoded production credentials & private tokens
DB_CONNECTION_STRING = "postgresql://db_admin:SuperSecretP@ssw0rd2026@prod-db.internal.corp:5432/main_db"
OPENAI_API_TOKEN = "sk-proj-4b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"
AWS_ACCESS_KEY = "AKIA9876543210ZYXWVU"
DEV_EMAIL = "harshith.raju@srkrec.edu.in"
INTERNAL_BACKEND_IP = "192.168.1.150"

def fetch_financial_records(account_id):
    # Vulnerability: Direct string interpolation into SQL query (SQL Injection - CWE-89)
    conn = psycopg2.connect(DB_CONNECTION_STRING)
    cursor = conn.cursor()
    query = "SELECT * FROM financial_records WHERE id = '" + account_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

def dispatch_cloud_job():
    # Vulnerability: Insecure TLS verification and exposed token header
    headers = {"Authorization": "Bearer " + OPENAI_API_TOKEN}
    response = requests.post(f"http://{INTERNAL_BACKEND_IP}:8443/dispatch", headers=headers, verify=False)
    return response.status_code
'''

def main():
    print("=" * 75)
    print(" [LOCK] PRIVACY-PRESERVING AI CODE REVIEW FRAMEWORK")
    print(" Dept. of CSE, SRKREC | Final Year Project")
    print("=" * 75)

    pipeline = PrivacyPreservingReviewPipeline(llm_backend="mock", min_sensitivity_threshold=2)

    print("\n[1] Submitting Source Code to 7-Layer Privacy Pipeline...")
    print(f"    Code Length: {len(DEMO_CODE)} characters | ~{len(DEMO_CODE)//4} estimated tokens")

    result = pipeline.process_code_review(
        raw_code=DEMO_CODE,
        user_intent="Audit for hardcoded credentials, SQL injection, and TLS vulnerabilities.",
        top_k_rag=3,
        restore_placeholders_locally=True
    )

    print("\n[2] LAYER 1 & 2: DETECTED SENSITIVE ENTITIES & DYNAMIC SENSITIVITY SCORES")
    print("-" * 75)
    for sub in result["substitutions"]:
        print(f"  * {sub['placeholder']:<26} | Category: {sub['category']:<24} | Score: {sub['score']}/3")

    print("\n[3] LAYER 3: CODE SANITIZATION & PRE-LLM DATA HIDING")
    print("-" * 75)
    print("--- SANITIZED CODE (SENT TO LLM - ALL SECRETS HIDDEN) ---")
    print(result["sanitized_code"])

    print("\n[4] LAYER 4: TOKEN OPTIMIZATION & RAG RETRIEVAL")
    print("-" * 75)
    stats = result["prompt_package"]["compression_stats"]
    print(f"  * Tokens Before: {stats['original_tokens']} -> After: {stats['optimized_tokens']} (Saved: {stats['savings_percent']}%)")
    print(f"  * RAG Injected CWE Rules: {[r['id'] for r in result['prompt_package']['rag_rules']]}")

    print("\n[5] LAYER 5 & 6: LLM AUDIT & CERTIFIED ZERO-LEAKAGE OUTPUT VALIDATION")
    print("-" * 75)
    print(f"  * Zero Egress Leakage Verified: {result['privacy_guarantee']['zero_raw_secrets_exposed']}")
    print(f"  * Output Leakage Rate: {result['privacy_guarantee']['output_leakage_rate'] * 100:.1f}%")

    print("\n[6] LAYER 7: LOCAL DE-ANONYMIZED FINAL SECURITY REPORT")
    print("=" * 75)
    print(result["final_report"])
    print("=" * 75)

    print("\n[7] PIPELINE LATENCY TELEMETRY (ms)")
    print("-" * 75)
    for step, duration in result["timing_ms"].items():
        print(f"  * {step:<28}: {duration:>6.2f} ms")

    print(f"\n[8] AUDIT LOG TAMPER-PROOF HASH: {result['audit_entry']['integrity_hash']}")
    print("=" * 75)
    print("[SUCCESS] PIPELINE EXECUTION COMPLETED WITH 0 ERRORS!\n")

if __name__ == "__main__":
    main()
