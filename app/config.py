import os


def mongo_uri() -> str:
    return os.getenv("MONGO_URI", "mongodb://localhost:27017")


def mongo_database() -> str:
    return os.getenv("MONGO_DATABASE", "cybersecurity_logs")


def postgres_dsn() -> str | None:
    return os.getenv("POSTGRES_DSN")


def max_upload_bytes() -> int:
    return int(os.getenv("MAX_UPLOAD_BYTES", "25000000"))
