"""
Assignment 11 - Production defense-in-depth support plugins.

These plugins add production-oriented layers that are not covered by the lab
alone: per-user rate limiting, audit logging, and monitoring/alerts.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from google.genai import types
from google.adk.plugins import base_plugin


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block abusive request bursts before they reach the model.

    This layer catches traffic abuse that input/output safety filters do not
    address, protecting both cost and availability.
    """

    def __init__(self, max_requests=10, window_seconds=60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.total_requests = 0
        self.blocked_requests = 0
        self.last_wait_time = 0

    async def on_user_message_callback(self, *, invocation_context, user_message):
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]
        self.total_requests += 1

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_requests += 1
            self.last_wait_time = max(1, int(self.window_seconds - (now - window[0])))
            return types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text=(
                            f"Rate limit exceeded. Please wait about {self.last_wait_time} seconds "
                            "before sending another request."
                        )
                    )
                ],
            )

        window.append(now)
        self.last_wait_time = 0
        return None


class AuditLogPlugin(base_plugin.BasePlugin):
    """Record interaction metadata for traceability and offline review.

    This layer does not block requests. It captures what happened, when it
    happened, and how long it took so the team can investigate incidents and
    produce evidence for the assignment report.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []
        self._active_requests = {}

    @staticmethod
    def _extract_text(content) -> str:
        text = ""
        if not content:
            return text
        parts = getattr(content, "parts", None)
        if parts:
            for part in parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        elif hasattr(content, "content") and getattr(content, "content", None):
            return AuditLogPlugin._extract_text(content.content)
        return text

    async def on_user_message_callback(self, *, invocation_context, user_message):
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        session_id = getattr(invocation_context, "session_id", None) or f"session-{user_id}"
        key = (user_id, session_id)
        self._active_requests[key] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "start_time": time.perf_counter(),
            "user_id": user_id,
            "session_id": session_id,
            "input": self._extract_text(user_message),
            "output": None,
            "blocked_by": None,
            "latency_ms": None,
        }
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        invocation_context = getattr(callback_context, "invocation_context", None)
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        session_id = getattr(invocation_context, "session_id", None) or f"session-{user_id}"
        key = (user_id, session_id)
        record = self._active_requests.pop(key, None)
        if record is None:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "start_time": time.perf_counter(),
                "user_id": user_id,
                "session_id": session_id,
                "input": "",
            }
        record["output"] = self._extract_text(llm_response)
        record["latency_ms"] = round((time.perf_counter() - record["start_time"]) * 1000, 2)
        record.pop("start_time", None)
        self.logs.append(record)
        return llm_response

    def record_manual_event(
        self,
        *,
        user_id: str,
        input_text: str,
        output_text: str,
        blocked_by: str | None,
        latency_ms: float,
        metadata: dict | None = None,
    ):
        """Record pipeline events outside of ADK callbacks."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "session_id": f"session-{user_id}",
            "input": input_text,
            "output": output_text,
            "blocked_by": blocked_by,
            "latency_ms": round(latency_ms, 2),
        }
        if metadata:
            entry.update(metadata)
        self.logs.append(entry)

    def export_json(self, filepath="audit_log.json"):
        path = Path(filepath)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=True), encoding="utf-8")
        return path


class MonitoringAlert:
    """Aggregate safety metrics and raise alerts when thresholds are exceeded."""

    def __init__(
        self,
        *,
        rate_limiter: RateLimitPlugin | None = None,
        input_guard=None,
        output_guard=None,
        audit_log: AuditLogPlugin | None = None,
        block_rate_threshold=0.35,
        judge_fail_threshold=0.15,
        rate_limit_threshold=3,
    ):
        self.rate_limiter = rate_limiter
        self.input_guard = input_guard
        self.output_guard = output_guard
        self.audit_log = audit_log
        self.block_rate_threshold = block_rate_threshold
        self.judge_fail_threshold = judge_fail_threshold
        self.rate_limit_threshold = rate_limit_threshold

    def collect_metrics(self) -> dict:
        total_logs = len(self.audit_log.logs) if self.audit_log else 0
        blocked_logs = sum(1 for log in (self.audit_log.logs if self.audit_log else []) if log.get("blocked_by"))
        rate_limit_hits = self.rate_limiter.blocked_requests if self.rate_limiter else 0
        total_requests = self.rate_limiter.total_requests if self.rate_limiter else total_logs
        judge_failures = self.output_guard.blocked_count if self.output_guard else 0

        return {
            "total_requests": total_requests,
            "block_rate": (blocked_logs / total_logs) if total_logs else 0.0,
            "rate_limit_hits": rate_limit_hits,
            "judge_fail_rate": (judge_failures / total_logs) if total_logs else 0.0,
            "input_blocks": self.input_guard.blocked_count if self.input_guard else 0,
            "output_blocks": self.output_guard.blocked_count if self.output_guard else 0,
            "redactions": self.output_guard.redacted_count if self.output_guard else 0,
        }

    def check_metrics(self) -> list[str]:
        metrics = self.collect_metrics()
        alerts = []
        if metrics["block_rate"] > self.block_rate_threshold:
            alerts.append(
                f"ALERT: block rate {metrics['block_rate']:.0%} exceeded threshold {self.block_rate_threshold:.0%}"
            )
        if metrics["rate_limit_hits"] >= self.rate_limit_threshold:
            alerts.append(
                f"ALERT: rate limit triggered {metrics['rate_limit_hits']} times"
            )
        if metrics["judge_fail_rate"] > self.judge_fail_threshold:
            alerts.append(
                f"ALERT: judge fail rate {metrics['judge_fail_rate']:.0%} exceeded threshold {self.judge_fail_threshold:.0%}"
            )
        return alerts
