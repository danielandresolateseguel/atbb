from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    DATABASE_URL = os.environ.get("DATABASE_URL")
    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", str(BASE_DIR / "audit_app.db")))
    UPLOADS_DIR = Path(os.environ.get("UPLOADS_DIR", str(BASE_DIR / "app" / "static" / "uploads")))
    AUDIT_EVIDENCE_DIR = UPLOADS_DIR / "audits"
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL")
    CLOUDINARY_FOLDER = os.environ.get("CLOUDINARY_FOLDER", "atbb")
