"""
Layer 4 - Subsystem B: Context-Aware RAG Security Knowledge Base.
Indexes Common Weakness Enumerations (CWE) and OWASP Top 10 rules.
Retrieves only security contexts relevant to the submitted code patterns,
preventing token bloat while boosting review accuracy.
"""

import math
import re
from typing import List, Dict, Any


class SecurityRAGKnowledgeBase:
    """
    In-memory vector & TF-IDF indexed security knowledge base.
    Delivers pinpoint security review guidelines based on code semantics.
    """

    KNOWLEDGE_CORPUS = [
        {
            "id": "CWE-798",
            "title": "Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "keywords": ["password", "api_key", "secret", "token", "credential", "auth", "key", "conn_str", "database_url"],
            "description": "Hardcoding credentials, API keys, or database passwords in source code exposes sensitive systems to unauthorized access.",
            "remediation": "Move all sensitive tokens to environment variables, system keychains, or secrets managers (e.g., AWS Secrets Manager, HashiCorp Vault)."
        },
        {
            "id": "CWE-89",
            "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "owasp": "A03:2021-Injection",
            "keywords": ["select", "insert", "update", "delete", "from", "where", "cursor.execute", "query", "sql", "format", "%s", "f\"select"],
            "description": "Concatenating or interpolating user-controlled input directly into SQL strings allows attackers to execute arbitrary database queries.",
            "remediation": "Always use parameterized queries or prepared statements via ORMs (e.g., SQLAlchemy, psycopg2 parameter binding)."
        },
        {
            "id": "CWE-78",
            "title": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "owasp": "A03:2021-Injection",
            "keywords": ["subprocess", "os.system", "popen", "shell=true", "exec", "eval", "spawn"],
            "description": "Passing unvalidated user inputs directly to system shells allows remote command execution.",
            "remediation": "Avoid invoking shell=True in subprocess; pass command arguments as explicit lists and validate inputs strictly."
        },
        {
            "id": "CWE-79",
            "title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "owasp": "A03:2021-Injection",
            "keywords": ["html", "render", "response", "innerhtml", "script", "document.write", "template", "markup"],
            "description": "Rendering unescaped user input into HTML allows attackers to inject malicious scripts into victims' browsers.",
            "remediation": "Ensure context-aware contextual encoding and enable Content Security Policy (CSP) headers."
        },
        {
            "id": "CWE-918",
            "title": "Server-Side Request Forgery (SSRF)",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "keywords": ["requests.get", "requests.post", "urllib", "http", "fetch", "url", "webhook", "curl"],
            "description": "Fetching remote resources using user-supplied URLs without validation can allow attackers to probe internal services and metadata APIs.",
            "remediation": "Validate target URLs against a strict allowlist of domains/IPs, and block private RFC 1918 addresses."
        },
        {
            "id": "CWE-319",
            "title": "Cleartext Transmission of Sensitive Information",
            "owasp": "A02:2021-Cryptographic Failures",
            "keywords": ["http://", "ftp://", "telnet", "unencrypted", "ssl=false", "verify=false"],
            "description": "Transmitting sensitive credentials or payload data over unencrypted channels leaves it vulnerable to eavesdropping and MITM attacks.",
            "remediation": "Enforce HTTPS/TLS 1.3 across all endpoints and verify server TLS certificates (verify=True)."
        },
        {
            "id": "CWE-502",
            "title": "Deserialization of Untrusted Data",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "keywords": ["pickle.loads", "yaml.load", "marshal", "unserialize", "jsonpickle"],
            "description": "Deserializing untrusted data streams can trigger arbitrary code execution during object reconstitution.",
            "remediation": "Use safe serializers like json.loads() or yaml.safe_load(); avoid using pickle for untrusted input."
        },
        {
            "id": "OWASP-LLM02",
            "title": "Sensitive Information Disclosure in LLMs",
            "owasp": "OWASP Top 10 for LLM Applications 2025",
            "keywords": ["prompt", "completion", "generate", "llm", "chat", "model", "placeholder", "pii"],
            "description": "LLM applications may inadvertently reveal proprietary intellectual property, personal identifiable data, or credentials in prompts or completions.",
            "remediation": "Implement client-side data pseudonymization before sending prompts, and run output sanitization on responses."
        }
    ]

    def __init__(self):
        # Precompute document frequencies for TF-IDF ranking
        self.doc_freqs: Dict[str, int] = {}
        self.total_docs = len(self.KNOWLEDGE_CORPUS)
        for doc in self.KNOWLEDGE_CORPUS:
            unique_terms = set(doc["keywords"])
            for term in unique_terms:
                self.doc_freqs[term] = self.doc_freqs.get(term, 0) + 1

    def retrieve(self, query_code: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Retrieves top_k relevant security standards matching the terms and syntax in query_code.
        """
        tokens = re.findall(r"\w+", query_code.lower())
        token_set = set(tokens)

        scored_docs = []
        for doc in self.KNOWLEDGE_CORPUS:
            score = 0.0
            for kw in doc["keywords"]:
                # Match either as standalone token or substring match
                if kw in token_set or any(kw in t for t in tokens):
                    df = self.doc_freqs.get(kw, 1)
                    idf = math.log((self.total_docs + 1) / (df + 1)) + 1.0
                    score += idf

            if score > 0.0:
                scored_docs.append({
                    "score": round(score, 3),
                    "id": doc["id"],
                    "title": doc["title"],
                    "owasp": doc["owasp"],
                    "description": doc["description"],
                    "remediation": doc["remediation"]
                })

        # Sort descending by relevance score
        scored_docs.sort(key=lambda x: x["score"], reverse=True)
        return scored_docs[:top_k]
