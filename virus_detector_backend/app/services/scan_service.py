import hashlib
import threading
import time
import uuid
from typing import Dict, Any, Optional


class InMemoryStore:
    """
    Simple in-memory store for scan analyses.
    Thread-safe via a re-entrant lock.
    """
    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create(self, data: Dict[str, Any]) -> str:
        with self._lock:
            analysis_id = str(uuid.uuid4())
            self._data[analysis_id] = data
            return analysis_id

    def update(self, analysis_id: str, updates: Dict[str, Any]) -> None:
        with self._lock:
            if analysis_id in self._data:
                self._data[analysis_id].update(updates)

    def get(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._data.get(analysis_id)

    def all(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            # return a shallow copy for safety
            return dict(self._data)


class HeuristicScanner:
    """
    Basic, pluggable heuristic scanner that simulates scanning latency and
    computes a risk score using simple rules. Designed to be replaceable with
    a real engine later.
    """
    def __init__(self, simulate_seconds: float = 1.2) -> None:
        self.simulate_seconds = simulate_seconds

    def _hash_content(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def _score_from_content(self, content: bytes) -> int:
        # Very simple heuristic for demo purposes:
        # - frequency of suspicious tokens
        # - entropy-like signal using unique byte count
        lower_text = content.decode("utf-8", errors="ignore").lower()
        suspicious_tokens = ["virus", "malware", "trojan", "worm", "payload", "exploit"]
        token_hits = sum(lower_text.count(tok) for tok in suspicious_tokens)
        unique_bytes = len(set(content))
        # map token hits and uniqueness to a score 0..100
        score = min(100, token_hits * 15 + max(0, unique_bytes - 180))
        return int(score)

    def _findings_from_content(self, content: bytes) -> Dict[str, Any]:
        lower_text = content.decode("utf-8", errors="ignore").lower()
        indicators = []
        for tok in ["virus", "malware", "trojan", "worm", "payload", "exploit"]:
            if tok in lower_text:
                indicators.append({"indicator": tok, "severity": "high"})
        if not indicators:
            indicators.append({"indicator": "no_known_indicators", "severity": "none"})
        return {"indicators": indicators}

    def scan(self, *, content: Optional[bytes] = None, hex_hash: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute a scan. Either content or hex_hash should be provided.
        If only hex_hash is provided, simulate a neutral score based on hash features.
        """
        time.sleep(self.simulate_seconds)  # simulate latency

        if content:
            computed_hash = self._hash_content(content)
            score = self._score_from_content(content)
            findings = self._findings_from_content(content)
        else:
            # Use hash string characteristics to simulate a score
            computed_hash = hex_hash or ""
            # rudimentary: count numeric chars in hash as a proxy
            digits = sum(1 for c in computed_hash if c.isdigit())
            score = min(100, digits)  # simple placeholder
            findings = {"indicators": [{"indicator": "hash_only_scan", "severity": "low"}]}

        status = "clean" if score < 30 else ("suspicious" if score < 70 else "malicious")
        return {
            "status": status,
            "score": score,
            "findings": findings,
            "hash": computed_hash,
        }


class ScanService:
    """
    Orchestrates scan submissions, background simulation, and retrieval.
    """

    def __init__(self, store: InMemoryStore, scanner: HeuristicScanner) -> None:
        self.store = store
        self.scanner = scanner

    # PUBLIC_INTERFACE
    def submit_scan(self, *, content: Optional[bytes], hex_hash: Optional[str]) -> str:
        """Submit a scan task, return analysis id. Initializes with status 'queued'."""
        record = {
            "status": "queued",
            "score": None,
            "findings": None,
            "hash": None,
            "submitted_at": time.time(),
            "completed_at": None,
        }
        analysis_id = self.store.create(record)

        # Start background thread for the "scan"
        thread = threading.Thread(
            target=self._perform_scan,
            args=(analysis_id, content, hex_hash),
            daemon=True,
        )
        thread.start()
        return analysis_id

    def _perform_scan(self, analysis_id: str, content: Optional[bytes], hex_hash: Optional[str]) -> None:
        self.store.update(analysis_id, {"status": "running"})
        try:
            result = self.scanner.scan(content=content, hex_hash=hex_hash)
            self.store.update(
                analysis_id,
                {
                    "status": "completed",
                    "score": result["score"],
                    "findings": result["findings"],
                    "hash": result["hash"],
                    "classification": result["status"],
                    "completed_at": time.time(),
                },
            )
        except Exception as exc:  # noqa: BLE001
            self.store.update(
                analysis_id,
                {"status": "failed", "error": str(exc), "completed_at": time.time()},
            )

    # PUBLIC_INTERFACE
    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis record by id."""
        return self.store.get(analysis_id)

    # PUBLIC_INTERFACE
    def get_report_summary(self) -> Dict[str, Any]:
        """Return aggregate summary of analyses."""
        all_data = self.store.all()
        total = len(all_data)
        statuses = {"queued": 0, "running": 0, "completed": 0, "failed": 0}
        totals = {"clean": 0, "suspicious": 0, "malicious": 0, "unknown": 0}

        for _, rec in all_data.items():
            status = rec.get("status") or "unknown"
            statuses[status] = statuses.get(status, 0) + 1
            classification = rec.get("classification") or "unknown"
            totals[classification] = totals.get(classification, 0) + 1

        avg_score = None
        scores = [rec["score"] for rec in all_data.values() if isinstance(rec.get("score"), int)]
        if scores:
            avg_score = sum(scores) / len(scores)

        return {
            "total": total,
            "statuses": statuses,
            "classification_counts": totals,
            "average_score": avg_score,
        }
