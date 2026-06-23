import os

from app import create_app


os.environ.setdefault("FLASK_DEBUG", "1")

app = create_app()


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
