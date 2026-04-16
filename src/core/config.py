"""
Core configuration helpers for Lab 11 / Assignment 11.
"""
import os


def has_api_key() -> bool:
    """Return True when a Google API key is available in the environment."""
    return bool(os.environ.get("GOOGLE_API_KEY"))


def setup_api_key(interactive: bool = False) -> bool:
    """Configure the runtime for Gemini usage.

    When `interactive` is False, the function will not prompt the user. This
    allows the project to run in offline/mock mode first, and the API key can
    be added later.
    """
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"

    if has_api_key():
        print("Google API key detected.")
        return True

    if interactive:
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
        print("API key loaded.")
        return True

    print("WARNING: GOOGLE_API_KEY not set. Running in offline/mock-friendly mode.")
    return False


ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
