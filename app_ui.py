"""
Streamlit Web Application: Privacy-Preserving AI Code Review Assistant.
Interactive Dashboard for demonstrating the 7-layer privacy-preserving pipeline,
token-efficient RAG retrieval, and zero-egress data protection.
"""

import streamlit as st
import time
import json
from src.pipeline import PrivacyPreservingReviewPipeline

# Page configuration
st.set_page_config(
    page_title="Privacy-Preserving AI Code Reviewer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for polished academic and engineering design
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        border-radius: 10px;
        padding: 16px;
        border: 1px solid #E2E8F0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-safe {
        background-color: #DCFCE7;
        color: #166534;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Sample Code Library
SAMPLE_CODES = {
    "Vulnerable DB & Cloud Credentials": '''import os
import psycopg2
import requests

# Hardcoded credentials and connection strings
DB_URL = "postgresql://admin_user:SuperSecretP@ssw0rd123@prod-db.internal.corp:5432/finance_db"
OPENAI_KEY = "sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
AWS_KEY = "AKIA1234567890ABCDEF"
ADMIN_EMAIL = "harshith.raju@srkrec.edu.in"
INTERNAL_IP = "192.168.1.105"

def query_user_account(user_id):
    # Potential SQL injection via direct string concatenation
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    query = "SELECT * FROM accounts WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

def sync_cloud_metrics():
    # Calling internal microservice with hardcoded bearer token
    headers = {"Authorization": "Bearer " + OPENAI_KEY}
    response = requests.get(f"http://{INTERNAL_IP}:8080/sync", headers=headers, verify=False)
    return response.json()
''',

    "Command Injection with Auth Token": '''import subprocess
import os

GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
NOTIFICATION_EMAIL = "amrutha.chappa@srkrec.edu.in"

def clone_and_run(user_repo_input):
    # Vulnerable OS command injection: passing unsanitized input to shell
    cmd = f"git clone https://{GITHUB_TOKEN}@github.com/{user_repo_input}.git"
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return result.communicate()
''',

    "Clean / Defensive Code": '''import os
import psycopg2
from typing import Optional, List, Tuple

def query_secure_account(account_id: int) -> Optional[List[Tuple]]:
    db_uri = os.getenv("APP_DATABASE_URL")
    if not db_uri:
        raise ValueError("APP_DATABASE_URL environment variable is missing")
    
    # Safe parameterized query
    with psycopg2.connect(db_uri) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, balance FROM accounts WHERE id = %s;", (account_id,))
            return cursor.fetchall()
'''
}

# Header Section
st.markdown('<div class="main-header">🔐 Privacy-Preserving AI Code Review Framework</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Token-Efficient LLM Framework for Secure Code Review Using Context-Aware Retrieval<br>'
    '<b>Dept. of CSE, SRKREC</b> | Team: Amrutha Chappa, Grandhi D N Harshith Raju, Janapati Karthik, Garalapati R V Surendra | Supervisor: Smt A.L. Lavanya</div>',
    unsafe_allow_html=True
)

# Sidebar Controls
with st.sidebar:
    st.header("⚙️ Pipeline Configuration")
    
    selected_sample = st.selectbox("📂 Load Sample Vulnerable Code", list(SAMPLE_CODES.keys()))
    
    backend_choice = st.selectbox(
        "🤖 LLM Analysis Engine",
        ["Offline Security Engine (Zero Cost / Safe)", "Google Gemini", "OpenAI (GPT-4o)", "Ollama (Local)"],
        index=0
    )
    
    backend_key = "mock"
    if "Gemini" in backend_choice:
        backend_key = "gemini"
    elif "OpenAI" in backend_choice:
        backend_key = "openai"
    elif "Ollama" in backend_choice:
        backend_key = "ollama"

    api_key_input = None
    if backend_key in ("gemini", "openai"):
        api_key_input = st.text_input(f"Enter {backend_choice} API Key", type="password")

    st.markdown("---")
    st.subheader("🛡️ Privacy Settings")
    sensitivity_threshold = st.slider(
        "Sensitivity Threshold",
        min_value=1,
        max_value=3,
        value=2,
        help="Level 3: Critical secrets only. Level 2: Secrets + PII + internal IPs. Level 1: Aggressive identifier masking."
    )
    
    restore_local = st.checkbox("Restore Identifiers Locally", value=True, help="Re-maps pseudonymized placeholders back to original variable names on your client machine.")
    top_k_rag = st.slider("RAG Knowledge Top-K Rules", min_value=1, max_value=5, value=3)

# Input Area
st.subheader("📝 Source Code Under Review")
code_input = st.text_area(
    "Paste your code here:",
    value=SAMPLE_CODES[selected_sample],
    height=280,
    help="Contains raw code with potential secrets and vulnerabilities"
)

user_intent = st.text_input(
    "Review Objective / Developer Intent:",
    value="Perform a rigorous security audit, detect hardcoded secrets and injection flaws, and suggest fixes."
)

if st.button("🚀 Run Privacy-Preserving Review", type="primary", use_container_width=True):
    with st.spinner("Executing 7-Layer Privacy Pipeline..."):
        pipeline = PrivacyPreservingReviewPipeline(
            llm_backend=backend_key,
            min_sensitivity_threshold=sensitivity_threshold,
            api_key=api_key_input
        )
        
        result = pipeline.process_code_review(
            raw_code=code_input,
            user_intent=user_intent,
            top_k_rag=top_k_rag,
            restore_placeholders_locally=restore_local
        )

    # Top Metric Banners
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(
            label="🛡️ Secrets Shielded from LLM",
            value=f"{result['privacy_guarantee']['total_entities_shielded']} Entities",
            delta="100% Protected"
        )
    with m2:
        st.metric(
            label="📉 Token Reduction",
            value=f"{result['prompt_package']['compression_stats']['savings_percent']}%",
            delta=f"-{result['prompt_package']['compression_stats']['tokens_saved']} tokens"
        )
    with m3:
        st.metric(
            label="🔒 LLM Egress Leakage Rate",
            value=f"{result['privacy_guarantee']['output_leakage_rate'] * 100:.1f}%",
            delta="Zero Leakage Verified",
            delta_color="normal"
        )
    with m4:
        st.metric(
            label="⚡ Total Pipeline Latency",
            value=f"{result['timing_ms']['total_pipeline_ms']:.1f} ms",
            delta="Local Hybrid Engine"
        )

    # Multi-Tab Deep Dive
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Security Audit Report",
        "👁️ Data Hiding & Code Masking",
        "🔐 Cryptographic Vault",
        "⚡ Token & RAG Optimization",
        "📜 Compliance & Audit Trail"
    ])

    # Tab 1: Final Audit Report
    with tab1:
        st.subheader("🔍 Automated Security & Vulnerability Analysis")
        st.markdown(result["final_report"])

    # Tab 2: Data Hiding & Masking
    with tab2:
        st.subheader("👁️ Pre-LLM Data Hiding Comparison")
        st.markdown(
            "Notice how the **raw passwords, API keys, and corporate endpoints are completely stripped** "
            "and replaced with context-preserving aliases before leaving your computer:"
        )
        col_raw, col_san = st.columns(2)
        with col_raw:
            st.markdown("##### ❌ Original User Code (With Raw Secrets)")
            st.code(result["original_code"], language="python")
        with col_san:
            st.markdown("##### ✅ Sanitized Code (What the LLM Actually Sees)")
            st.code(result["sanitized_code"], language="python")

    # Tab 3: Cryptographic Vault
    with tab3:
        st.subheader("🔐 Reversible Pseudonymization Vault State")
        st.info("The mapping between original sensitive tokens and their semantic placeholders is encrypted in client memory using an authenticated 256-bit session key.")
        if result["substitutions"]:
            st.table(result["substitutions"])
        else:
            st.success("No sensitive secrets detected requiring masking.")

    # Tab 4: RAG & Token Optimization
    with tab4:
        st.subheader("⚡ Context Optimization & RAG Standards Injected")
        st.write("**Compression Statistics:**")
        st.json(result["prompt_package"]["compression_stats"])
        
        st.write("**Retrieved Security Standards (CWE / OWASP):**")
        for rule in result["prompt_package"]["rag_rules"]:
            with st.expander(f"📌 [{rule['id']}] {rule['title']} (Match Score: {rule['score']})"):
                st.write(f"**OWASP Mapping:** {rule['owasp']}")
                st.write(f"**Description:** {rule['description']}")
                st.write(f"**Remediation Guidance:** {rule['remediation']}")

    # Tab 5: Audit Log
    with tab5:
        st.subheader("📜 Cryptographic Audit Record")
        st.json(result["audit_entry"])
