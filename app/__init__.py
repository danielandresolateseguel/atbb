from flask import Flask

from config import Config

from app.models import close_db, init_db
from app.routes import main


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["AUDIT_EVIDENCE_DIR"].mkdir(parents=True, exist_ok=True)

    app.register_blueprint(main)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    return app


app = create_app()
