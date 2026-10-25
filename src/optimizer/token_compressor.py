"""
Layer 4 - Subsystem A: Token Compressor & Context Optimizer.
Reduces token payload size before LLM submission by pruning redundant whitespace,
collapsing repetitive documentation blocks, and eliminating non-essential comments.
"""

import re
from typing import Tuple, Dict, Any


class TokenCompressor:
    """
    Minimizes code and prompt tokens while preserving AST semantics and syntax.
    """

    def __init__(self):
        pass

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """
        Approximates BPE token count (~4 characters per token in standard LLM tokenizers).
        """
        if not text:
            return 0
        return max(1, len(text) // 4)

    def compress_code(self, code: str, remove_trivial_comments: bool = True) -> Tuple[str, Dict[str, Any]]:
        """
        Compresses source code to optimize token usage without breaking Python indentation.
        """
        original_tokens = self.estimate_tokens(code)
        lines = code.splitlines()
        compressed_lines = []

        prev_empty = False
        for line in lines:
            stripped = line.strip()

            # Skip consecutive empty lines
            if not stripped:
                if not prev_empty:
                    compressed_lines.append("")
                    prev_empty = True
                continue
            prev_empty = False

            # Filter trivial or decorative comment lines (e.g. # ----------------)
            if remove_trivial_comments:
                if stripped.startswith("#") and re.match(r"^#\s*[-=*~_#]{3,}$", stripped):
                    continue
                if stripped.lower() in ("# todo", "# fixme", "# note", "# pass"):
                    continue

            # Strip trailing whitespace on each line
            compressed_lines.append(line.rstrip())

        optimized_code = "\n".join(compressed_lines).strip()
        optimized_tokens = self.estimate_tokens(optimized_code)

        savings = max(0, original_tokens - optimized_tokens)
        savings_pct = round((savings / original_tokens * 100), 2) if original_tokens > 0 else 0.0

        stats = {
            "original_tokens": original_tokens,
            "optimized_tokens": optimized_tokens,
            "tokens_saved": savings,
            "savings_percent": savings_pct,
            "original_chars": len(code),
            "optimized_chars": len(optimized_code),
        }

        return optimized_code, stats
