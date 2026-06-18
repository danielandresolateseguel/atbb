import os

from flask import Flask, flash, jsonify, redirect, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config

from app.models import close_db, init_db
from app.routes import main


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["AUDIT_EVIDENCE_DIR"].mkdir(parents=True, exist_ok=True)

    debug_raw = str(os.environ.get("FLASK_DEBUG") or "").strip().lower()
    if debug_raw in {"1", "true", "yes", "y", "on"}:
        app.config["DEBUG"] = True

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
