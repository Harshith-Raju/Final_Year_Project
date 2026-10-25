"""
Layer 3 - Subsystem B: Context-Preserving Semantic Placeholder Generator.
Creates uniform, deterministic, syntax-compliant aliases that allow the LLM to
accurately comprehend code architecture without disclosing sensitive values.
"""

from typing import Dict


class PlaceholderGenerator:
    """
    Produces deterministic semantic tokens that preserve grammatical context.
    For example:
    - OpenAI / Cloud keys -> __API_KEY_1__
    - Database strings -> __DB_CONNECTION_1__
    - Passwords -> __AUTH_PASSWORD_1__
    - Email addresses -> __USER_EMAIL_1__
    """

    CATEGORY_PREFIX_MAP: Dict[str, str] = {
        "OPENAI_API_KEY": "API_KEY",
        "GITHUB_TOKEN": "AUTH_TOKEN",
        "AWS_ACCESS_KEY": "CLOUD_KEY",
        "AWS_SECRET_KEY": "CLOUD_SECRET",
        "GOOGLE_API_KEY": "API_KEY",
        "SLACK_TOKEN": "SERVICE_TOKEN",
        "STRIPE_KEY": "PAYMENT_KEY",
        "JWT_TOKEN": "JWT_TOKEN",
        "DATABASE_URL": "DB_CONNECTION",
        "PRIVATE_KEY_HEADER": "PRIVATE_KEY",
        "BEARER_TOKEN": "BEARER_TOKEN",
        "GENERIC_SECRET_IN_STRING": "SECRET_CREDENTIAL",
        "CREDENTIAL_ASSIGNMENT": "CREDENTIAL",
        "HIGH_ENTROPY_KEY": "SECRET_TOKEN",
        "EMAIL_ADDRESS": "USER_EMAIL",
        "IP_ADDRESS": "HOST_IP",
        "IP_ADDRESS_V6": "HOST_IP6",
        "PHONE_NUMBER": "PHONE_NUM",
        "INTERNAL_ENDPOINT": "INTERNAL_ENDPOINT",
        "FINANCIAL_IDENTIFIER": "PAYMENT_CARD",
        "ENV_VARIABLE": "ENV_VAR",
        "CODE_IDENTIFIER": "IDENTIFIER",
    }

    def __init__(self):
        self.counters: Dict[str, int] = {}

    def generate(self, category: str) -> str:
        """Returns the next available indexed placeholder for the given category."""
        prefix = self.CATEGORY_PREFIX_MAP.get(category, "SENSITIVE_ENTITY")
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        count = self.counters[prefix]
        return f"__{prefix}_{count}__"

    def reset(self):
        """Resets generator sequence counters."""
        self.counters.clear()
