"""LASSO Dashboard — custom Jinja2 template filters."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from flask import Flask


def _register_filters(app: Flask) -> None:
    """Register custom Jinja2 template filters."""

    @app.template_filter("timeago")
    def timeago_filter(iso_str: str) -> str:
        """Format an ISO timestamp as a relative time string."""
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = now - dt
            seconds = int(delta.total_seconds())
            if seconds < 60:
                return f"{seconds}s ago"
            if seconds < 3600:
                return f"{seconds // 60}m ago"
            if seconds < 86400:
                return f"{seconds // 3600}h ago"
            return f"{seconds // 86400}d ago"
        except (ValueError, TypeError):
            return str(iso_str)

    @app.template_filter("truncate_id")
    def truncate_id_filter(value: str, length: int = 8) -> str:
        return value[:length] if value else ""

    @app.template_filter("tojson_pretty")
    def tojson_pretty_filter(value: Any) -> str:
        return json.dumps(value, indent=2, default=str)
