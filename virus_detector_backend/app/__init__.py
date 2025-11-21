import logging
from typing import Any, Dict

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_smorest import Api

from .routes.health import blp as health_blp
from .routes.scan import blp as scan_blp


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def _create_app_config(app: Flask) -> None:
    # Ocean Professional style naming and OpenAPI setup
    app.config["API_TITLE"] = "Virus Detection API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/docs"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = ""
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"success": False, "data": None, "error": {"message": "Bad Request"}}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "data": None, "error": {"message": "Not Found"}}), 404

    @app.errorhandler(422)
    def unprocessable_entity(e):
        # webargs / marshmallow validation errors may surface here
        messages = getattr(e, "data", {}).get("messages", {})
        return jsonify({"success": False, "data": None, "error": {"message": "Validation error", "details": messages}}), 422

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"success": False, "data": None, "error": {"message": "Internal Server Error"}}), 500


def create_app() -> Flask:
    """
    Application factory for the Virus Detection backend.
    Initializes CORS, OpenAPI, error handling, health and scanning routes.
    """
    _configure_logging()
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    CORS(app, resources={r"/*": {"origins": "*"}})

    _create_app_config(app)

    api = Api(app)
    api.register_blueprint(health_blp)
    api.register_blueprint(scan_blp)

    _register_error_handlers(app)
    return app


# Create a module-level app for simple run.py imports
app = create_app()
