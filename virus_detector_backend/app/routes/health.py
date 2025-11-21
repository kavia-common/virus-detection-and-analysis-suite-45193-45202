from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint("Health", "health", url_prefix="/", description="Health check routes")


@blp.route("/")
class RootHealth(MethodView):
    """
    Simple root health to align with existing openapi and preview probes.
    """
    def get(self):
        return {"status": "ok"}


@blp.route("/healthz")
class HealthCheck(MethodView):
    """
    Health check endpoint for liveness/readiness probes.
    """
    def get(self):
        return {"status": "ok"}
