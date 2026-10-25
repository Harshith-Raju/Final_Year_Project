"""
Layer 1 - Subsystem A: Abstract Syntax Tree (AST) Code Parser.
Extracts syntax nodes, string literals, secret-like assignments, and environment lookups
from source code to provide structural context before token masking.
"""

import ast
import re
from typing import List, Dict, Any, Optional


class ASTCodeParser:
    """
    Parses code using Python's built-in AST library.
    Falls back gracefully to structural regex scanning for other languages (JS, TS, Java, etc.)
    """

    SUSPICIOUS_VAR_NAMES = {
        "api_key", "apikey", "secret", "secret_key", "password", "passwd", "pwd",
        "token", "access_token", "auth_token", "bearer", "private_key", "db_password",
        "database_url", "conn_str", "connection_string", "client_secret", "jwt",
        "credentials", "auth", "secret_token", "webhook_url"
    }

    def __init__(self):
        pass

    def parse_python(self, code: str) -> List[Dict[str, Any]]:
        """
        Parses Python code and extracts detailed metadata on potential sensitive nodes.
        """
        extracted = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fallback to regex-based structural parser if code is partial or non-Python
            return self.parse_generic(code)

        for node in ast.walk(tree):
            # 1. Variable Assignments: e.g. api_key = "sk-..." or DB_PASS = "12345"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    var_name = self._get_target_name(target)
                    if var_name:
                        is_suspicious_var = any(s in var_name.lower() for s in self.SUSPICIOUS_VAR_NAMES)
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            extracted.append({
                                "type": "ast_assignment",
                                "var_name": var_name,
                                "value": node.value.value,
                                "line": getattr(node, "lineno", 1),
                                "is_suspicious_name": is_suspicious_var,
                                "context": f"Assignment to '{var_name}'"
                            })

            # 2. Dictionary Keys / Literals: e.g. {"password": "xyz", "Authorization": "Bearer ..."}
            elif isinstance(node, ast.Dict):
                for key_node, val_node in zip(node.keys, node.values):
                    key_val = getattr(key_node, "value", None) if isinstance(key_node, ast.Constant) else None
                    if key_val and isinstance(key_val, str):
                        is_suspicious_key = any(s in key_val.lower() for s in self.SUSPICIOUS_VAR_NAMES)
                        if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                            extracted.append({
                                "type": "ast_dict_entry",
                                "var_name": key_val,
                                "value": val_node.value,
                                "line": getattr(val_node, "lineno", 1),
                                "is_suspicious_name": is_suspicious_key,
                                "context": f"Dictionary key '{key_val}'"
                            })

            # 3. Environment variable lookups: os.environ.get('SECRET') or os.getenv('SECRET')
            elif isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in ("os.getenv", "os.environ.get", "getenv"):
                    if node.args and isinstance(node.args[0], ast.Constant):
                        env_key = node.args[0].value
                        extracted.append({
                            "type": "ast_env_call",
                            "var_name": str(env_key),
                            "value": str(env_key),
                            "line": getattr(node, "lineno", 1),
                            "is_suspicious_name": True,
                            "context": f"Environment lookup: {func_name}('{env_key}')"
                        })

            # 4. Standalone string literals:
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Filter out trivial strings like docstrings or short strings
                if len(node.value.strip()) >= 8:
                    extracted.append({
                        "type": "ast_string_literal",
                        "var_name": None,
                        "value": node.value,
                        "line": getattr(node, "lineno", 1),
                        "is_suspicious_name": False,
                        "context": "String literal in code"
                    })

        return extracted

    def parse_generic(self, code: str) -> List[Dict[str, Any]]:
        """
        Regex-assisted parser for code snippets in JavaScript, JSON, YAML, SQL, or bash.
        """
        extracted = []
        assignment_pattern = re.compile(
            r"""(?:const|let|var|export|val)?\s*([a-zA-Z_0-9]+)\s*[:=]\s*["']([^"']{4,})["']""",
            re.IGNORECASE
        )
        for lineno, line in enumerate(code.splitlines(), start=1):
            matches = assignment_pattern.finditer(line)
            for m in matches:
                var_name, val = m.group(1), m.group(2)
                is_suspicious = any(s in var_name.lower() for s in self.SUSPICIOUS_VAR_NAMES)
                extracted.append({
                    "type": "generic_assignment",
                    "var_name": var_name,
                    "value": val,
                    "line": lineno,
                    "is_suspicious_name": is_suspicious,
                    "context": f"Identifier '{var_name}'"
                })
        return extracted

    def _get_target_name(self, target: ast.AST) -> Optional[str]:
        if isinstance(target, ast.Name):
            return target.id
        elif isinstance(target, ast.Attribute):
            return target.attr
        return None

    def _get_call_name(self, func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            val = self._get_call_name(func.value)
            return f"{val}.{func.attr}" if val else func.attr
        return ""
