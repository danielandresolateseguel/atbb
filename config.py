from pathlib import Path
from datetime import timedelta
import os


BASE_DIR = Path(__file__).resolve().parent


def env_int(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except ValueError:
        return int(default)


def env_float(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return float(default)
    try:
        return float(str(raw).strip())
    except ValueError:
        return float(default)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    DATABASE_URL = os.environ.get("DATABASE_URL")
    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", str(BASE_DIR / "audit_app.db")))
    UPLOADS_DIR = Path(os.environ.get("UPLOADS_DIR", str(BASE_DIR / "app" / "static" / "uploads")))
    AUDIT_EVIDENCE_DIR = UPLOADS_DIR / "audits"
    MAX_CONTENT_LENGTH = env_int("MAX_CONTENT_LENGTH_MB", 50) * 1024 * 1024
    MAX_SIGNATURE_BYTES = env_int("MAX_SIGNATURE_BYTES_KB", 512) * 1024
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL")
    CLOUDINARY_FOLDER = os.environ.get("CLOUDINARY_FOLDER", "atbb")
    REPORT_TARGET_APPROVAL_RATE = env_int("REPORT_TARGET_APPROVAL_RATE", 85)
    REPORT_TARGET_AVERAGE_SCORE = env_float("REPORT_TARGET_AVERAGE_SCORE", 95.0)
    AUDIT_OFFICIAL_FROM_DATE = (os.environ.get("AUDIT_OFFICIAL_FROM_DATE") or "").strip() or None
    PERMANENT_SESSION_LIFETIME = timedelta(days=3)
