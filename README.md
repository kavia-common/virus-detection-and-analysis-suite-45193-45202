# Virus Detection and Analysis Suite

Backend: Flask (flask-smorest) with OpenAPI docs.

Docs URL (preview): /docs

Health:
- GET /healthz -> {"status":"ok"}
- GET / -> {"status":"ok"}

Endpoints:
- POST /api/scan
  Request JSON: {"content": "string content"} OR {"hash": "abc123..."}
  Response JSON: {"success": true, "data": {"id":"<uuid>","status":"queued"}, "error": null}

- GET /api/analysis/<id>
  Response JSON: {"success": true, "data": {"id": "...", "status": "running|completed|failed", "score": 0-100, "classification": "clean|suspicious|malicious", "findings": {...}, "hash": "...", "submitted_at": <ts>, "completed_at": <ts|null>}, "error": null}

- GET /api/report
  Response JSON: {"success": true, "data": {"total": n, "statuses": {...}, "classification_counts": {...}, "average_score": <float|null>}, "error": null}

Run locally:
- python run.py (binds to 0.0.0.0:3001)

Notes:
- In-memory storage for scans; replaceable with a DB later.
- Heuristic scanner simulates latency and computes a simple score.
- Consistent response format: {success, data, error}.
- OpenAPI available at /docs and JSON at /openapi.json.