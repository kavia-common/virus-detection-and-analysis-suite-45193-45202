from marshmallow import Schema, fields, validate


class BaseResponseSchema(Schema):
    success = fields.Boolean(required=True, description="Indicates if the request was successful.")
    data = fields.Raw(allow_none=True, description="Payload for successful responses.")
    error = fields.Raw(allow_none=True, description="Error detail for failed responses.")


class ScanRequestSchema(Schema):
    content = fields.String(required=False, allow_none=True, description="File content to scan (UTF-8 string for demo). Provide either content or hash.")
    hash = fields.String(required=False, allow_none=True, description="SHA-256 or other hash to scan if content not provided.")
    # Enforce at least one provided via route logic.


class ScanSubmissionResponseDataSchema(Schema):
    id = fields.String(required=True, description="Unique analysis identifier.")
    status = fields.String(required=True, validate=validate.OneOf(["queued", "running", "completed", "failed"]), description="Initial status of analysis task.")


class AnalysisResponseDataSchema(Schema):
    id = fields.String(required=True, description="Analysis identifier.")
    status = fields.String(required=True, description="Current status of analysis.")
    score = fields.Integer(allow_none=True, description="Risk score 0..100.")
    classification = fields.String(allow_none=True, description="clean | suspicious | malicious")
    findings = fields.Raw(allow_none=True, description="Findings and indicators.")
    hash = fields.String(allow_none=True, description="Computed or provided hash.")
    submitted_at = fields.Float(required=False, description="Timestamp when submitted.")
    completed_at = fields.Float(allow_none=True, description="Timestamp when completed.")


class ReportSummarySchema(Schema):
    total = fields.Integer(required=True)
    statuses = fields.Dict(keys=fields.String(), values=fields.Integer())
    classification_counts = fields.Dict(keys=fields.String(), values=fields.Integer())
    average_score = fields.Float(allow_none=True)
