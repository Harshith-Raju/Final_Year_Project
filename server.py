"""
Standalone Pure-Python Web Dashboard for Privacy-Preserving AI Code Review Framework.
Zero third-party framework dependencies - runs immediately and reliably on Python 3.14+!
"""

import http.server
import socketserver
import json
import urllib.parse
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.pipeline import PrivacyPreservingReviewPipeline

PORT = 8501

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy-Preserving AI Code Review Dashboard</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --bg: #090d16;
            --surface: #111827;
            --surface-card: #1f2937;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-blue: #38bdf8;
            --border: #374151;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 24px; min-height: 100vh; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
        .header h1 { font-size: 1.6rem; color: #60a5fa; }
        .header p { color: var(--text-muted); font-size: 0.9rem; margin-top: 4px; }
        .badge { background: #064e3b; color: #34d399; padding: 6px 14px; border-radius: 9999px; font-weight: bold; font-size: 0.85rem; border: 1px solid #059669; }
        
        .code-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
        .card h2 { font-size: 1.15rem; margin-bottom: 12px; color: #93c5fd; display: flex; align-items: center; justify-content: space-between; }
        textarea { width: 100%; height: 280px; background: #030712; color: #e0f2fe; border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: Consolas, Monaco, monospace; font-size: 0.88rem; resize: vertical; line-height: 1.45; }
        textarea:focus { outline: 1px solid var(--primary); }
        
        .action-row { display: flex; gap: 12px; margin-top: 14px; }
        .btn { background: var(--primary); color: white; border: none; border-radius: 6px; padding: 12px 24px; font-weight: bold; cursor: pointer; transition: 0.2s; font-size: 1rem; flex: 1; }
        .btn:hover { background: var(--primary-dark); }
        .btn-secondary { background: #374151; color: #e5e7eb; border: 1px solid #4b5563; }
        .btn-secondary:hover { background: #4b5563; }
        
        .edge-presets { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
        .preset-btn { background: #1e293b; color: #93c5fd; border: 1px solid var(--border); padding: 6px 12px; border-radius: 6px; font-size: 0.8rem; cursor: pointer; }
        .preset-btn:hover { background: #2563eb; color: white; }
        
        .metrics-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }
        .metric-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; text-align: center; }
        .metric-value { font-size: 1.5rem; font-weight: bold; color: #38bdf8; margin-top: 4px; }
        .metric-title { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; }
        
        .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px; }
        .tab-btn { background: none; border: none; color: var(--text-muted); font-weight: 600; padding: 10px 18px; cursor: pointer; border-radius: 6px; font-size: 0.95rem; }
        .tab-btn.active { background: #1e3a8a; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        pre { background: #030712; padding: 16px; border-radius: 8px; border: 1px solid var(--border); color: #cbd5e1; font-family: Consolas, Monaco, monospace; font-size: 0.88rem; white-space: pre-wrap; max-height: 480px; overflow-y: auto; line-height: 1.45; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.88rem; }
        th, td { text-align: left; padding: 10px 14px; border: 1px solid var(--border); }
        th { background: #0f172a; color: #93c5fd; }
        
        .toggle-btn { background: #1f2937; border: 1px solid var(--border); color: #38bdf8; padding: 4px 10px; border-radius: 6px; font-size: 0.78rem; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔐 Privacy-Preserving AI Code Review Framework</h1>
            <p>Token-Efficient LLM Framework for Secure Code Review Using Context-Aware Retrieval | Dept. of CSE, SRKREC</p>
        </div>
        <div>
            <span class="badge">🔒 Zero-Egress Secrets Shield</span>
        </div>
    </div>

    <!-- Quick Edge Case Presets for Demonstrations -->
    <div style="margin-bottom: 12px; font-size: 0.85rem; color: var(--text-muted);">
        <b>⚡ Live Demonstration Edge Cases & Failure Scenarios:</b>
    </div>
    <div class="edge-presets">
        <button class="preset-btn" onclick="loadCase('real_world')">1. Real-World Multi-Cloud (AWS + OpenAI + DB)</button>
        <button class="preset-btn" onclick="loadCase('sql_injection')">2. SQL Injection with Hardcoded JWT</button>
        <button class="preset-btn" onclick="loadCase('command_injection')">3. Shell Command Injection + GitHub Token</button>
        <button class="preset-btn" onclick="loadCase('edge_subdomain')">4. Internal IP / Corporate URL Exfiltration</button>
        <button class="preset-btn" onclick="loadCase('clean_code')">5. Clean Code (False Positive Test)</button>
    </div>

    <div class="code-grid">
        <!-- Panel 1: Your Input Code -->
        <div class="card">
            <h2>
                <span>📝 Your Original Submitted Code (Input)</span>
                <button class="toggle-btn" onclick="clearInput()">Clear</button>
            </h2>
            <textarea id="code_input" placeholder="Paste your custom Python code with API keys, database strings, or functions here..."></textarea>
            <div class="action-row">
                <button class="btn" onclick="runReview()">🚀 Execute 7-Layer Privacy Pipeline</button>
            </div>
        </div>

        <!-- Panel 2: Sanitized Code (What LLM sees) -->
        <div class="card">
            <h2>
                <span>👁️ Sanitized Code (What the LLM Actually Receives)</span>
                <span style="font-size: 0.8rem; color: #34d399;">Secrets Masked</span>
            </h2>
            <textarea id="sanitized_display" readonly placeholder="Click Execute to see your code with all sensitive credentials automatically replaced by safe semantic placeholders (__API_KEY_1__, etc.)..."></textarea>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 14px;">
                ✅ Notice how raw credentials never leave this box. The LLM only analyzes the safe placeholders!
            </p>
        </div>
    </div>

    <!-- Live Telemetry Bar -->
    <div class="metrics-row">
        <div class="metric-box">
            <div class="metric-title">Secrets Shielded</div>
            <div class="metric-value" id="metric_shielded">0 Entities</div>
        </div>
        <div class="metric-box">
            <div class="metric-title">Output Leakage Rate</div>
            <div class="metric-value" style="color: #34d399;" id="metric_leakage">0.0% (Zero)</div>
        </div>
        <div class="metric-box">
            <div class="metric-title">RAG Rules Injected</div>
            <div class="metric-value" id="metric_rag">0 CWEs</div>
        </div>
        <div class="metric-box">
            <div class="metric-title">Pipeline Latency</div>
            <div class="metric-value" id="metric_latency">0.0 ms</div>
        </div>
    </div>

    <!-- Multi-Tab Details -->
    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('report')">📋 Security Review & Direct Patched Code</button>
        <button class="tab-btn" onclick="switchTab('vault')">🔐 Encrypted Vault (Substitutions)</button>
        <button class="tab-btn" onclick="switchTab('rag')">⚡ RAG Injected Knowledge</button>
        <button class="tab-btn" onclick="switchTab('audit')">📜 Tamper-Proof Audit Hash</button>
    </div>

    <div id="tab_report" class="tab-content active">
        <div class="card">
            <h2>🛡️ Security Vulnerabilities & Refactored Fix (Layer 7 Restored Locally)</h2>
            <pre id="report_display">Submit your code above and click 'Execute 7-Layer Privacy Pipeline' to view vulnerability detections and the refactored secure code fix customized for your functions.</pre>
        </div>
    </div>

    <div id="tab_vault" class="tab-content">
        <div class="card">
            <h2>🔐 In-Memory Pseudonymization Vault</h2>
            <div id="vault_table_wrapper"><p style="color: var(--text-muted); padding: 12px;">Run review to inspect mapped aliases.</p></div>
        </div>
    </div>

    <div id="tab_rag" class="tab-content">
        <div class="card">
            <h2>⚡ Context-Aware Retrieval (RAG) Security Standards</h2>
            <pre id="rag_display">Relevant OWASP and CWE standards will appear here upon review.</pre>
        </div>
    </div>

    <div id="tab_audit" class="tab-content">
        <div class="card">
            <h2>📜 Local Cryptographic Audit Hash</h2>
            <pre id="audit_display">Audit record will be displayed here.</pre>
        </div>
    </div>

    <script>
        const TEST_CASES = {
            real_world: `import os
import psycopg2
import requests

# Hardcoded production credentials & private tokens
DB_CONNECTION_STRING = "postgresql://prod_app:SuperSecretP@ss2026@internal-db.corp:5432/finance_db"
OPENAI_API_TOKEN = "sk-proj-4f9A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
ADMIN_EMAIL = "harshith.raju@srkrec.edu.in"
INTERNAL_IP = "10.142.0.24"

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
    response = requests.post("http://" + INTERNAL_IP + ":8443/dispatch", headers=headers, verify=False)
    return response.status_code`,

            sql_injection: `import psycopg2

JWT_SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"

def authenticate_and_fetch(username, input_password):
    conn = psycopg2.connect("dbname=users_db user=postgres")
    cur = conn.cursor()
    # High risk SQL injection:
    cur.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{input_password}'")
    return cur.fetchone()`,

            command_injection: `import subprocess

GITHUB_ACCESS_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"

def clone_user_repository(repo_name):
    # High risk OS command injection:
    cmd = f"git clone https://{GITHUB_ACCESS_TOKEN}@github.com/{repo_name}.git"
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()`,

            edge_subdomain: `import requests

DEV_URL = "https://admin.internal.corp/admin/reset"
DEV_IP = "192.168.1.150"
API_AUTH_BEARER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sometokenfragment"

def trigger_internal_sync():
    # Calling internal network endpoint
    return requests.get(DEV_URL, headers={"Authorization": API_AUTH_BEARER}, verify=False)`,

            clean_code: `import os
import psycopg2

def safe_account_query(account_id: int):
    # Safe parameterized query with environment configuration
    db_url = os.getenv("APP_DB_URL")
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM accounts WHERE id = %s;", (account_id,))
            return cur.fetchone()`
        };

        window.onload = function() {
            document.getElementById('code_input').value = TEST_CASES.real_world;
        };

        function loadCase(key) {
            document.getElementById('code_input').value = TEST_CASES[key];
        }

        function clearInput() {
            document.getElementById('code_input').value = "";
            document.getElementById('code_input').focus();
        }

        function switchTab(name) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('tab_' + name).classList.add('active');
        }

        async function runReview() {
            const btn = document.querySelector('.btn');
            btn.innerText = "⏳ Running 7 Layers...";
            btn.disabled = true;

            const code = document.getElementById('code_input').value;
            if (!code.trim()) {
                alert("Please paste or type code into the input box first!");
                btn.innerText = "🚀 Execute 7-Layer Privacy Pipeline";
                btn.disabled = false;
                return;
            }

            try {
                const res = await fetch('/api/review', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({code: code})
                });
                const data = await res.json();

                document.getElementById('sanitized_display').value = data.sanitized_code;
                document.getElementById('report_display').innerText = data.final_report;
                document.getElementById('metric_shielded').innerText = data.substitutions.length + " Entities";
                document.getElementById('metric_leakage').innerText = (data.privacy_guarantee.output_leakage_rate * 100).toFixed(1) + "% (Zero)";
                document.getElementById('metric_rag').innerText = data.prompt_package.rag_rules.length + " CWEs";
                document.getElementById('metric_latency').innerText = data.timing_ms.total_pipeline_ms.toFixed(1) + " ms";

                // Vault Table
                if (data.substitutions && data.substitutions.length > 0) {
                    let tableHtml = "<table><tr><th>Semantic Placeholder</th><th>Category</th><th>Sensitivity Score</th></tr>";
                    data.substitutions.forEach(s => {
                        tableHtml += `<tr><td><code>${s.placeholder}</code></td><td>${s.category}</td><td>${s.score}/3</td></tr>`;
                    });
                    tableHtml += "</table>";
                    document.getElementById('vault_table_wrapper').innerHTML = tableHtml;
                } else {
                    document.getElementById('vault_table_wrapper').innerHTML = "<p style='color: #10b981; padding: 12px;'>✅ No critical hardcoded secrets detected in this snippet.</p>";
                }

                // RAG
                let ragText = "";
                data.prompt_package.rag_rules.forEach(r => {
                    ragText += `[${r.id}] ${r.title} (${r.owasp})\\nFocus: ${r.description}\\nRemediation: ${r.remediation}\\n\\n`;
                });
                document.getElementById('rag_display').innerText = ragText || "No matching CWE rules triggered.";

                // Audit
                document.getElementById('audit_display').innerText = JSON.stringify(data.audit_entry, null, 2);

            } catch (err) {
                alert("Error running review: " + err);
            } finally {
                btn.innerText = "🚀 Execute 7-Layer Privacy Pipeline";
                btn.disabled = false;
            }
        }
    </script>
</body>
</html>
"""

pipeline_instance = PrivacyPreservingReviewPipeline(llm_backend="mock")

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "running"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/review":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
            code = payload.get("code", "")

            result = pipeline_instance.process_code_review(raw_code=code)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

def main():
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        print(f"[OK] Web Dashboard active on http://127.0.0.1:{PORT}")
        sys.stdout.flush()
        httpd.serve_forever()

if __name__ == "__main__":
    main()
