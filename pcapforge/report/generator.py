"""HTML + PDF report generator for PCAPForge."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from pcapforge.types.network import PcapSummary

_TEMPLATE_DIR = Path(__file__).parent


def _filesizeformat(value: int, count: bool = False) -> str:
    if count:
        if value >= 1_000_000:
            return f"{value/1_000_000:.1f}M"
        if value >= 1_000:
            return f"{value/1_000:.1f}K"
        return str(value)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _first_n(iterable, n):
    return list(iterable)[:n]


def generate_html(summary: "PcapSummary", output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    env.filters["filesizeformat"] = _filesizeformat
    env.filters["first_n"] = _first_n
    template = env.get_template("template.html")
    html = template.render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        s=summary.summary,
        stats=summary.stats,
        version="0.1.0",
    )
    output.write_text(html, encoding="utf-8")
    return output


def generate_pdf(summary: "PcapSummary", output_path: str | Path) -> Path:
    output = Path(output_path)
    try:
        import weasyprint  # type: ignore
    except ImportError:
        html_path = output.with_suffix(".html")
        return generate_html(summary, html_path)
    html_path = output.with_suffix(".html")
    generate_html(summary, html_path)
    weasyprint.HTML(filename=str(html_path)).write_pdf(str(output))
    return output
