"""Tests for the KASA web dashboard module and CLI dashboard commands."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from kasa.dashboard.html import render_dashboard_html
from kasa.dashboard.server import (
    DashboardRequestHandler,
    _find_free_port,
    _run_full_analysis,
    start_dashboard,
)


def test_render_dashboard_html_contains_critical_sections() -> None:
    """Dashboard HTML must include key UI elements and embedded JSON."""
    sample_data = {
        "risk": {"score": 70, "rating": "critical"},
        "findings": [
            {
                "id": "KASA-SYSCTL-MMAP_MIN_ADDR",
                "title": "mmap min addr too low",
                "description": "Kernel zero page can be mapped",
                "severity": "high",
                "category": "sysctl-hardening",
                "recommendation": "Set vm.mmap_min_addr=65536",
            }
        ],
        "ai_report": {
            "summary": "High risk detected",
            "overall_risk_assessment": "Several severe issues.",
            "attack_scenarios": [
                {
                    "name": "Null Pointer Dereference Exploit",
                    "description": "Attacker maps page zero and triggers kernel null deref",
                    "affected_findings": ["KASA-SYSCTL-MMAP_MIN_ADDR"],
                    "likelihood": "HIGH",
                    "impact": "Root privilege escalation",
                    "attacker_profile": "local",
                }
            ],
            "steps": [],
            "priority_order": [],
        },
    }

    html = render_dashboard_html(sample_data)
    assert "<!DOCTYPE html>" in html
    assert "KASA" in html
    assert "Potential Attack Possibilities" in html
    assert "Security Findings" in html
    assert "AI Remediation Plan" in html
    assert "KASA-SYSCTL-MMAP_MIN_ADDR" in html
    assert "Null Pointer Dereference Exploit" in html


def test_run_full_analysis_returns_dict() -> None:
    """_run_full_analysis() must return dict with snapshot, findings, risk."""
    data = _run_full_analysis()
    assert isinstance(data, dict)
    assert "snapshot" in data
    assert "findings" in data
    assert "risk" in data


def test_find_free_port() -> None:
    """_find_free_port() should return an integer >= start_port."""
    port = _find_free_port(9000)
    assert isinstance(port, int)
    assert port >= 9000


def test_start_dashboard_non_blocking() -> None:
    """start_dashboard(block=False) should instantiate HTTPServer and return."""
    server, port = start_dashboard(
        port=9990,
        open_browser=False,
        initial_data={"risk": {"score": 0, "rating": "low"}, "findings": []},
        block=False,
    )
    assert server is not None
    assert port >= 9990
    server.server_close()


def test_dashboard_command_in_cli() -> None:
    """The 'dashboard' command and '--dashboard' flags must be in cli.py."""
    import inspect
    import kasa.cli as cli_module

    source = inspect.getsource(cli_module)
    assert "def dashboard(" in source
    assert "--dashboard" in source
