import os

from flask import Flask, flash, jsonify, redirect, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime, timezone, timedelta

from config import Config

from app.models import close_db, init_db
from app.routes import main


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["UPLOADS_DIR"].mkdir(parents=True, exist_ok=True)
    app.config["AUDIT_EVIDENCE_DIR"].mkdir(parents=True, exist_ok=True)

    # #region debug-point post-commit-500
    def _dbg_post_commit_500(hypothesis_id, msg, data=None, run_id="pre-fix", location="app/__init__.py"):
        try:
            if os.environ.get("DEBUG_POST_COMMIT_500") != "1":
                return
            import json as _json, urllib.request as _ur, time as _time

            _p = ".dbg/post-commit-500.env"
            _u, _s = "http://127.0.0.1:7777/event", "post-commit-500"
            try:
                with open(_p, encoding="utf-8") as _f:
                    _c = _f.read()
                for _line in _c.splitlines():
                    if _line.startswith("DEBUG_SERVER_URL="):
                        _u = _line.split("=", 1)[1].strip() or _u
                    elif _line.startswith("DEBUG_SESSION_ID="):
                        _s = _line.split("=", 1)[1].strip() or _s
            except Exception:
                pass

            payload = {
                "sessionId": _s,
                "runId": run_id,
                "hypothesisId": hypothesis_id,
                "location": location,
                "msg": f"[DEBUG] {msg}",
                "data": data or {},
                "ts": int(_time.time() * 1000),
            }
            _ur.urlopen(
                _ur.Request(_u, data=_json.dumps(payload, ensure_ascii=False).encode("utf-8"), headers={"Content-Type": "application/json"}),
                timeout=1.5,
            ).read()
        except Exception:
            return

    @app.before_request
    def _dbg_post_commit_500_before_request():
        try:
            _dbg_post_commit_500(
                "E",
                "request",
                {
                    "method": request.method,
                    "path": request.path,
                    "query": request.query_string.decode("utf-8", "ignore") if request.query_string else "",
                    "accept": str(request.headers.get("Accept") or ""),
                    "is_secure": bool(request.is_secure),
                    "user_id": request.cookies.get(app.config.get("SESSION_COOKIE_NAME", "atbb_session"), "")[:16],
                    "tz": str(app.config.get("APP_TIMEZONE") or ""),
                },
                location="app/__init__.py:before_request",
            )
        except Exception:
            return

    @app.teardown_request
    def _dbg_post_commit_500_teardown_request(exc):
        try:
            if not exc:
                return
            import traceback as _tb

            _dbg_post_commit_500(
                "A",
                "exception",
                {
                    "type": type(exc).__name__,
                    "detail": str(exc),
                    "path": request.path if request else None,
                    "traceback": _tb.format_exc(),
                },
                location="app/__init__.py:teardown_request",
            )
        except Exception:
            return
    # #endregion

    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        ZoneInfo = None

    def _app_timezone():
        name = (app.config.get("APP_TIMEZONE") or "").strip() or "America/Argentina/Buenos_Aires"
        if ZoneInfo:
            try:
                return ZoneInfo(name)
            except Exception:
                return timezone(timedelta(hours=-3))
        return timezone(timedelta(hours=-3))

    def _parse_any_datetime(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1]
            try:
                return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            try:
                return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None

    def ar_dt(value, fmt="%Y-%m-%d %H:%M"):
        dt = _parse_any_datetime(value)
        if not dt:
            return "-"
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(_app_timezone()).strftime(fmt)

    app.jinja_env.filters["ar_dt"] = ar_dt

    debug_raw = str(os.environ.get("FLASK_DEBUG") or "").strip().lower()
    if debug_raw in {"1", "true", "yes", "y", "on"}:
        app.config["DEBUG"] = True

    # ===== Logger FORZADO a INFO (para que los current_app.logger.info() de share/confirm SIEMPRE se vean) =====
    import logging
    try:
        import sys as _sys
        # Root logger
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            stream=_sys.stdout,
            force=True,
        )
        # Asegurarse werkzeug / flask logger
        for _lname in ("app", "werkzeug", "flask.app", ""):
            _l = logging.getLogger(_lname)
            try:
                _l.setLevel(logging.INFO)
                if not _l.handlers:
                    _h = logging.StreamHandler(_sys.stdout)
                    _h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
                    _l.addHandler(_h)
            except Exception:
                pass
    except Exception:
        pass

    if app.config.get("SECRET_KEY") == "dev-secret-key-change-me" and not app.debug and not app.testing:
        raise RuntimeError("SECRET_KEY no está configurada. Define la variable de entorno SECRET_KEY.")

    app.register_blueprint(main)
    app.teardown_appcontext(close_db)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self' https:;",
        )
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_entity_too_large(_error):
        max_bytes = int(app.config.get("MAX_CONTENT_LENGTH") or 0)
        max_mb = round(max_bytes / (1024 * 1024), 1) if max_bytes else None
        detail = (
            f"El tamaño total de la auditoría supera el límite permitido ({max_mb} MB). "
            "Reduce el tamaño o la cantidad de fotos e intenta nuevamente."
            if max_mb is not None
            else "El tamaño total de la auditoría supera el límite permitido. Reduce el tamaño o la cantidad de fotos."
        )

        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "request_entity_too_large", "detail": detail}), 413

        flash(detail, "error")
        return redirect(request.referrer or url_for("main.new_audit"))

    with app.app_context():
        init_db()

    return app
