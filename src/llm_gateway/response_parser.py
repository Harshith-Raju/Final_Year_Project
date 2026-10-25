"""
Layer 5 - Subsystem C: Security Response Parser.
Extracts structured vulnerability objects, security ratings, and remediation blocks
from the LLM text completion.
"""

import re
from typing import Dict, Any, List


class SecurityReportParser:
    """
    Parses unstructured LLM markdown review output into structured telemetry.
    """

    @staticmethod
    def parse_report(raw_text: str) -> Dict[str, Any]:
        rating = 8  # default
        rating_match = re.search(r"(?:Rating|Score):\s*(\d+(?:\.\d+)?)\s*\/\s*10", raw_text, re.IGNORECASE)
        if rating_match:
            try:
                rating = float(rating_match.group(1))
            except ValueError:
                pass

        # Extract vulnerabilities
        vulnerabilities: List[Dict[str, str]] = []
        vuln_blocks = re.findall(r"###\s*\d+\.\s*(.*?)(?=\n###|\n##|$)", raw_text, re.DOTALL)
        for block in vuln_blocks:
            lines = block.strip().splitlines()
            title = lines[0].strip() if lines else "Security Risk"
            cwe_match = re.search(r"CWE-\d+", block)
            sev_match = re.search(r"Severity:\s*(Critical|High|Medium|Low)", block, re.IGNORECASE)

            vulnerabilities.append({
                "title": title,
                "cwe": cwe_match.group(0) if cwe_match else "CWE-General",
                "severity": sev_match.group(1).capitalize() if sev_match else "Medium",
                "details": block.strip()
            })

        return {
            "rating": rating,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "raw_text": raw_text
        }
