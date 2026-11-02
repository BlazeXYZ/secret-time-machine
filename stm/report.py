"""Render scan results into a single self-contained HTML file."""
from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = Path(__file__).with_name("report_template.html")


def render_html(result: dict) -> str:
    # Escaping "<" keeps any string in the data from closing the <script> block early.
    payload = json.dumps(result, ensure_ascii=False).replace("<", "\\u003c")
    return TEMPLATE.read_text(encoding="utf-8").replace("__STM_DATA__", payload, 1)
