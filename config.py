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

def env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    normalized = str(raw).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    APP_TIMEZONE = (os.environ.get("APP_TIMEZONE") or "America/Argentina/Buenos_Aires").strip() or "America/Argentina/Buenos_Aires"
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
    FINDING_EFFECTIVENESS_CHECK_DAYS = env_int("FINDING_EFFECTIVENESS_CHECK_DAYS", 30)
    FINDING_EFFECTIVENESS_ALERT_DAYS = env_int("FINDING_EFFECTIVENESS_ALERT_DAYS", 7)
    AUDIT_OFFICIAL_FROM_DATE = (os.environ.get("AUDIT_OFFICIAL_FROM_DATE") or "").strip() or None
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=env_int("SESSION_LIFETIME_MINUTES", 720))
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "atbb_session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = (os.environ.get("SESSION_COOKIE_SAMESITE") or "Lax").strip() or "Lax"
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    INITIAL_TECHNICIAN_PASSWORD = os.environ.get("INITIAL_TECHNICIAN_PASSWORD", "SoftBerardi2026!")
    TEMPLATES_AUTO_RELOAD = True
    EXPLAIN_TEMPLATE_LOADING = False
    WEATHER_CACHE_TTL_SECONDS = env_int("WEATHER_CACHE_TTL_SECONDS", 10800)
    WEATHER_ERROR_TTL_SECONDS = env_int("WEATHER_ERROR_TTL_SECONDS", 3600)
    WEATHER_OPEN_METEO_API_KEY = os.getenv("WEATHER_OPEN_METEO_API_KEY") or None
    WEATHERAPI_COM_KEY = os.getenv("WEATHERAPI_COM_KEY") or None
    WEATHER_PROVIDER_PRIORITY = os.getenv("WEATHER_PROVIDER_PRIORITY") or "wa,om"
    WEATHER_PRECIP_MODERATE_MM = env_float("WEATHER_PRECIP_MODERATE_MM", 3.0)
    WEATHER_PRECIP_BLOCK_MM = env_float("WEATHER_PRECIP_BLOCK_MM", 8.0)
    WEATHER_SNOW_BLOCK_CM = env_float("WEATHER_SNOW_BLOCK_CM", 3.0)
    WEATHER_WIND_BLOCK_KMH = env_float("WEATHER_WIND_BLOCK_KMH", 70.0)
    WEATHER_ZONDA_WIND_BLOCK_KMH = env_float("WEATHER_ZONDA_WIND_BLOCK_KMH", 50.0)
    WEATHER_ENABLED = env_bool("WEATHER_ENABLED", True)
    # Token compartido para la sincronización automática de OT desde el Sistema Integral.
    # Si no está configurado, los endpoints /api/si/* requieren login de sesión normal.
    SI_API_TOKEN = os.environ.get("SI_API_TOKEN") or None
    SI_MSSQL_HOST = (os.environ.get("SI_MSSQL_HOST") or "").strip() or None
    SI_MSSQL_PORT = env_int("SI_MSSQL_PORT", 1435)
    SI_MSSQL_DATABASE = (os.environ.get("SI_MSSQL_DATABASE") or "").strip() or None
    SI_MSSQL_USER = (os.environ.get("SI_MSSQL_USER") or "").strip() or None
    SI_MSSQL_PASSWORD = os.environ.get("SI_MSSQL_PASSWORD") or None
    SI_PULL_WINDOW_MINUTES = env_int("SI_PULL_WINDOW_MINUTES", 15)
    SI_PULL_CONNECT_TIMEOUT_SECONDS = env_int("SI_PULL_CONNECT_TIMEOUT_SECONDS", 30)
    SI_PULL_QUERY_TIMEOUT_SECONDS = env_int("SI_PULL_QUERY_TIMEOUT_SECONDS", 120)
    SI_PULL_BATCH_SIZE = env_int("SI_PULL_BATCH_SIZE", 500)
    SI_PULL_PAUSE_MS = env_int("SI_PULL_PAUSE_MS", 1500)
    SI_PULL_LOCK_TIMEOUT_SECONDS = env_int("SI_PULL_LOCK_TIMEOUT_SECONDS", 900)
    # Carga inicial de OT no realizadas: ventana en días desde la fecha de la OT.
    # Después de la primera corrida el pull pasa a modo incremental por id.
    SI_PULL_NO_REALIZADAS_LOOKBACK_DAYS = env_int("SI_PULL_NO_REALIZADAS_LOOKBACK_DAYS", 90)
    # Disparo on-demand: al abrir la vista de OT se lanza el pull en segundo plano
    # si pasó el intervalo mínimo y no hay una corrida en curso.
    SI_PULL_ON_DEMAND = env_bool("SI_PULL_ON_DEMAND", True)
    SI_PULL_ON_DEMAND_MIN_INTERVAL_MINUTES = env_int("SI_PULL_ON_DEMAND_MIN_INTERVAL_MINUTES", 10)
