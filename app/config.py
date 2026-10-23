import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)


def mongo_uri() -> str:
    return os.getenv("MONGO_URI", "mongodb://localhost:27017")


def mongo_database() -> str:
    return os.getenv("MONGO_DATABASE", "cybersecurity_logs")


def postgres_dsn() -> str | None:
    return os.getenv("POSTGRES_DSN")


def max_upload_bytes() -> int:
    return int(os.getenv("MAX_UPLOAD_BYTES", "25000000"))


def jwt_secret_key() -> str:
    key = os.getenv("JWT_SECRET_KEY")
    if not key or not key.strip():
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not configured. "
            "A secure secret key must be provided before starting the application."
        )
    return key.strip()


def jwt_algorithm() -> str:
    return os.getenv("JWT_ALGORITHM", "HS256")


def jwt_expire_minutes() -> int:
    return int(os.getenv("JWT_EXPIRE_MINUTES", "60"))


def admin_bootstrap_username() -> str | None:
    return os.getenv("ADMIN_USERNAME")


def admin_bootstrap_password() -> str | None:
    return os.getenv("ADMIN_PASSWORD")


def admin_bootstrap_email() -> str | None:
    return os.getenv("ADMIN_EMAIL")


def login_rate_limit_max() -> int:
    return int(os.getenv("LOGIN_RATE_LIMIT_MAX", "5"))


def login_rate_limit_window_seconds() -> int:
    return int(os.getenv("LOGIN_RATE_LIMIT_WINDOW", "300"))
