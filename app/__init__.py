from flask import Flask, flash, jsonify, redirect, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config

from app.models import close_db, init_db
from app.routes import main


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["AUDIT_EVIDENCE_DIR"].mkdir(parents=True, exist_ok=True)

    app.register_blueprint(main)
    app.teardown_appcontext(close_db)

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


app = create_app()
