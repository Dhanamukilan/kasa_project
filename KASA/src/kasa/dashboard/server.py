"""Local web dashboard server for KASA security analysis and attack visualization."""

from __future__ import annotations

import json
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from kasa.analyzers.config import KernelConfigAnalyzer
from kasa.analyzers.filesystem import FilesystemAnalyzer
from kasa.analyzers.kernel import KernelAnalyzer
from kasa.analyzers.modules import ModuleAnalyzer
from kasa.analyzers.normalize import FindingNormalizer
from kasa.analyzers.risk import RiskScorer
from kasa.analyzers.selinux import SELinuxAnalyzer
from kasa.analyzers.sysctl import SysctlAnalyzer
from kasa.collectors.system import SystemCollector
from kasa.dashboard.html import render_dashboard_html
from kasa.models.analysis import AnalysisResult


def _run_full_analysis() -> dict[str, Any]:
    """Execute live system telemetry collection and analyzers."""
    snapshot = SystemCollector().collect()

    analyzers = [
        KernelAnalyzer(),
        KernelConfigAnalyzer(),
        ModuleAnalyzer(),
        FilesystemAnalyzer(),
        SELinuxAnalyzer(),
        SysctlAnalyzer(),
    ]

    findings = []
    for analyzer in analyzers:
        findings.extend(analyzer.analyze(snapshot))

    normalized_findings = FindingNormalizer().normalize(findings)
    result = AnalysisResult(findings=normalized_findings)
    risk = RiskScorer().assess(result.findings)

    return {
        "snapshot": snapshot.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "risk": risk.model_dump(mode="json"),
        "ai_report": None,
    }


def _find_free_port(start_port: int = 8080) -> int:
    """Find an available TCP port starting from start_port."""
    for port in range(start_port, start_port + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for KASA dashboard and API endpoints."""

    current_data: dict[str, Any] = {}

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default stdout request logging."""

    def do_GET(self) -> None:
        """Route GET requests."""
        if self.path in ("/", "/index.html"):
            html_content = render_dashboard_html(self.current_data)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))
            return

        if self.path == "/api/scan":
            self.current_data.update(_run_full_analysis())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.current_data).encode("utf-8"))
            return

        if self.path == "/api/ai":
            try:
                from kasa.ai.remediation import RemediationAdvisor
                from kasa.models.finding import Finding
                from kasa.models.risk import RiskAssessment, RiskRating

                findings = [Finding(**f) for f in self.current_data.get("findings", [])]
                raw_risk = self.current_data.get("risk", {})
                risk = RiskAssessment(
                    score=raw_risk.get("score", 0),
                    rating=RiskRating(raw_risk.get("rating", "low")),
                    finding_count=raw_risk.get("finding_count", len(findings)),
                )
                kernel_rel = (
                    self.current_data.get("snapshot", {})
                    .get("kernel", {})
                    .get("kernel", {})
                    .get("release")
                )

                advisor = RemediationAdvisor()
                report = advisor.advise(findings, risk, kernel_rel)
                report_dict = report.model_dump(mode="json", exclude={"raw_response"})
                self.current_data["ai_report"] = report_dict

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(report_dict).encode("utf-8"))
            except Exception as exc:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(exc)}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def start_dashboard(
    *,
    port: int = 8080,
    open_browser: bool = True,
    initial_data: dict[str, Any] | None = None,
    block: bool = True,
) -> tuple[HTTPServer, int]:
    """Start the KASA web dashboard server.

    Args:
        port: Preferred starting port (auto-increments if in use).
        open_browser: Whether to open the default web browser.
        initial_data: Pre-populated analysis data or None to scan immediately.
        block: Whether to block the calling thread (serve_forever).

    Returns:
        ``(server_instance, bound_port)``
    """
    actual_port = _find_free_port(port)

    if initial_data is None:
        data = _run_full_analysis()
    else:
        data = initial_data

    DashboardRequestHandler.current_data = data

    server = ThreadingHTTPServer(("127.0.0.1", actual_port), DashboardRequestHandler)
    url = f"http://127.0.0.1:{actual_port}"

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    if block:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.server_close()

    return server, actual_port
