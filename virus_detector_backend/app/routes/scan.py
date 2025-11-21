import logging
from flask.views import MethodView
from flask_smorest import Blueprint

from ..models.schemas import (
    BaseResponseSchema,
    ScanRequestSchema,
)
from ..services.scan_service import InMemoryStore, HeuristicScanner, ScanService

# Initialize shared service singletons
_store = InMemoryStore()
_scanner = HeuristicScanner(simulate_seconds=1.2)
_service = ScanService(store=_store, scanner=_scanner)

log = logging.getLogger(__name__)

blp = Blueprint(
    "Virus Scanning",
    "scanning",
    url_prefix="/api",
    description="Endpoints for scan submission, analysis retrieval, and reporting.",
)


@blp.route("/scan")
class SubmitScan(MethodView):
    """
    Submit a scan request. Provide either 'content' (string) or 'hash'.
    Returns an id for later retrieval.
    """

    @blp.arguments(ScanRequestSchema, location="json")
    @blp.response(200, BaseResponseSchema, description="Scan submission accepted.")
    @blp.doc(
        summary="Submit scan",
        description="Submit a virus scan for content or a hash. Returns an analysis id and initial status.",
        operationId="submitScan",
        tags=["Virus Scanning"],
    )
    def post(self, json_data):
        content = json_data.get("content")
        hex_hash = json_data.get("hash")

        if not content and not hex_hash:
            return {
                "success": False,
                "data": None,
                "error": {"message": "Either 'content' or 'hash' must be provided."},
            }, 400

        # Accept string content and encode to bytes for heuristic scanning
        content_bytes = content.encode("utf-8") if isinstance(content, str) else None

        analysis_id = _service.submit_scan(content=content_bytes, hex_hash=hex_hash)
        result = {"id": analysis_id, "status": "queued"}
        return {"success": True, "data": result, "error": None}


@blp.route("/analysis/<string:analysis_id>")
class GetAnalysis(MethodView):
    """
    Retrieve analysis details using an id returned by /api/scan.
    """

    @blp.response(200, BaseResponseSchema, description="Analysis details response.")
    @blp.doc(
        summary="Get analysis",
        description="Fetch analysis details including status, score, classification, findings, and timestamps.",
        operationId="getAnalysis",
        tags=["Virus Scanning"],
        parameters=[{"name": "analysis_id", "in": "path", "required": True, "schema": {"type": "string"}}],
    )
    def get(self, analysis_id: str):
        data = _service.get_analysis(analysis_id)
        if not data:
            return {"success": False, "data": None, "error": {"message": "Analysis not found"}}, 404

        payload = {
            "id": analysis_id,
            "status": data.get("status"),
            "score": data.get("score"),
            "classification": data.get("classification"),
            "findings": data.get("findings"),
            "hash": data.get("hash"),
            "submitted_at": data.get("submitted_at"),
            "completed_at": data.get("completed_at"),
        }
        return {"success": True, "data": payload, "error": None}


@blp.route("/report")
class ReportSummary(MethodView):
    """
    Get an aggregate summary of analyses.
    """

    @blp.response(200, BaseResponseSchema, description="Aggregate report summary.")
    @blp.doc(
        summary="Report summary",
        description="Returns totals, status distribution, classification counts, and average score across all analyses.",
        operationId="reportSummary",
        tags=["Virus Scanning"],
    )
    def get(self):
        summary = _service.get_report_summary()
        return {"success": True, "data": summary, "error": None}
