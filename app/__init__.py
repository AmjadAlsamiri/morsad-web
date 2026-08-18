from pathlib import Path
from flask import Flask
from app.db import init_app as init_db


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.from_object('app.config.Config')
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_db(app)

    # Register blueprints
    from app.scans.routes import scans_bp
    app.register_blueprint(scans_bp)

    return app
