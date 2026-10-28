"""KASA command-line interface."""

import json
from pathlib import Path
from typing import Annotated

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

import typer

from kasa.analyzers.config import KernelConfigAnalyzer
from kasa.analyzers.filesystem import FilesystemAnalyzer
from kasa.analyzers.kernel import KernelAnalyzer
from kasa.analyzers.modules import ModuleAnalyzer
from kasa.analyzers.normalize import FindingNormalizer
from kasa.analyzers.risk import RiskScorer
from kasa.analyzers.selinux import SELinuxAnalyzer
from kasa.analyzers.sysctl import SysctlAnalyzer
from kasa.collectors.system import SystemCollector
from kasa.dashboard.server import start_dashboard
from kasa.models.analysis import AnalysisResult

app = typer.Typer(
    name="kasa",
    help="AI-assisted Linux Kernel Attack Surface Analyzer.",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    dashboard_flag: Annotated[
        bool,
        typer.Option(
            "--dashboard",
            "-d",
            help="Launch the interactive KASA web dashboard immediately.",
        ),
    ] = False,
) -> None:
    """KASA command-line interface."""
    if dashboard_flag:
        typer.echo("🚀 Launching KASA Web Dashboard...")
        start_dashboard(port=8080, open_browser=True, block=True)
        raise typer.Exit()


@app.command()
def version() -> None:
    """Display the KASA version."""
    from kasa import __version__

    typer.echo(f"KASA {__version__}")


@app.command()
def collect(
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output the complete evidence snapshot as JSON.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write the complete evidence snapshot to a JSON file.",
        ),
    ] = None,
) -> None:
    """Collect Linux kernel attack-surface evidence."""
    snapshot = SystemCollector().collect()

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            snapshot.model_dump_json(indent=2),
            encoding="utf-8",
        )
        typer.echo(f"Evidence written to: {output}")
        return

    if json_output:
        typer.echo(snapshot.model_dump_json(indent=2))
        return

    typer.echo("KASA Linux Kernel Attack Surface Analyzer")
    typer.echo()
    typer.echo("Kernel")
    typer.echo(f"  Release: {snapshot.kernel.kernel.release}")
    typer.echo()
    typer.echo("Modules")
    typer.echo(f"  Loaded: {len(snapshot.modules.loaded)}")
    typer.echo(f"  Built-in: {len(snapshot.modules.builtin)}")
    typer.echo()
    typer.echo("Filesystem")
    typer.echo(f"  Mounts: {len(snapshot.filesystems.mounts)}")
    typer.echo(f"  Supported: {len(snapshot.filesystems.supported_filesystems)}")
    typer.echo()
    typer.echo(f"Sysctl Parameters Collected: {len(snapshot.sysctl_params)}")
    typer.echo()

    if snapshot.errors:
        typer.echo(f"Collection errors: {len(snapshot.errors)}")
    else:
        typer.echo("Status: Collection successful")


def _run_analysis() -> tuple[AnalysisResult, object]:
    """Run the full analysis pipeline and return (result, risk)."""
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

    return result, risk


@app.command()
def analyze(
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output security findings and risk assessment as JSON.",
        ),
    ] = False,
    dashboard_view: Annotated[
        bool,
        typer.Option(
            "--dashboard",
            "-d",
            help="Open the interactive web dashboard with the analysis results.",
        ),
    ] = False,
) -> None:
    """Analyze collected evidence for security findings."""
    result, risk = _run_analysis()

    if json_output:
        output = {
            "findings": [
                finding.model_dump(mode="json") for finding in result.findings
            ],
            "risk": risk.model_dump(mode="json"),  # type: ignore[union-attr]
        }

        typer.echo(json.dumps(output, indent=2))
        if not dashboard_view:
            return

    if not json_output:
        typer.echo("KASA Security Analysis")
        typer.echo()
        typer.echo(f"Risk Score: {risk.score}")  # type: ignore[union-attr]
        typer.echo(f"Risk Rating: {risk.rating.value.upper()}")  # type: ignore[union-attr]
        typer.echo()
        typer.echo(f"Findings: {result.total}")
        typer.echo()

        if not result.findings:
            typer.echo("No security findings detected.")
        else:
            for finding in result.findings:
                typer.echo(f"[{finding.severity.value.upper()}] {finding.id}")
                typer.echo(f"  {finding.title}")
                typer.echo(f"  {finding.description}")

                if finding.recommendation:
                    typer.echo(f"  Recommendation: {finding.recommendation}")

                typer.echo()

    if dashboard_view:
        typer.echo("\n🚀 Launching Web Dashboard...")
        snapshot = SystemCollector().collect()
        initial_data = {
            "snapshot": snapshot.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "risk": risk.model_dump(mode="json"),  # type: ignore[union-attr]
            "ai_report": None,
        }
        start_dashboard(initial_data=initial_data, block=True)


@app.command()
def providers() -> None:
    """Show available AI providers and whether their API key is set."""
    from kasa.ai.providers import list_providers

    typer.echo("KASA AI Providers")
    typer.echo()
    typer.echo(f"  {'Provider':<14} {'Default Model':<40} {'Key Variable':<24} Status")
    typer.echo("  " + "─" * 100)

    for p in list_providers():
        status = "✓ READY" if p["available"] else "✗ no key"
        key_var = p["key_found"] or p["env_vars"][0]  # type: ignore[index]
        typer.echo(
            f"  {p['name']:<14} {p['default_model']:<40} {key_var:<24} {status}"
        )

    typer.echo()
    typer.echo("Single Key Universal Setup:")
    typer.echo("  export KASA_API_KEY=\"your-key\"   (automatically detects provider from key format)")
    typer.echo()
    typer.echo("Or use provider-specific variables:")
    typer.echo("  DEEPSEEK_API_KEY    → https://platform.deepseek.com/api_keys")
    typer.echo("  OPENROUTER_API_KEY  → https://openrouter.ai/keys  (Qwen3, DeepSeek, Llama …)")
    typer.echo("  TOGETHER_API_KEY    → https://api.together.xyz/settings/api-keys")
    typer.echo("  FIREWORKS_API_KEY   → https://fireworks.ai/account/api-keys")
    typer.echo("  GEMINI_API_KEY      → https://aistudio.google.com/apikey")


@app.command()
def dashboard(
    port: Annotated[
        int,
        typer.Option(
            "--port",
            "-p",
            help="Preferred port for the web dashboard (default 8080).",
        ),
    ] = 8080,
    no_browser: Annotated[
        bool,
        typer.Option(
            "--no-browser",
            help="Do not automatically open the web browser.",
        ),
    ] = False,
    findings_file: Annotated[
        Path | None,
        typer.Option(
            "--from-file",
            "-f",
            help="Load a previously saved JSON analysis file.",
        ),
    ] = None,
) -> None:
    """Launch the interactive KASA web dashboard."""
    initial_data = None
    if findings_file is not None:
        if not findings_file.exists():
            typer.echo(f"Error: file not found: {findings_file}", err=True)
            raise typer.Exit(1)
        try:
            initial_data = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception as exc:
            typer.echo(f"Error reading JSON file: {exc}", err=True)
            raise typer.Exit(1) from exc

    typer.echo(f"🚀 Starting KASA Web Dashboard on port {port}...")
    start_dashboard(
        port=port,
        open_browser=not no_browser,
        initial_data=initial_data,
        block=True,
    )


@app.command()
def ai(  # noqa: A001
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            help=(
                "API key for the chosen provider. "
                "Auto-detected from KASA_API_KEY or provider env vars when omitted."
            ),
        ),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option(
            "--provider",
            "-p",
            help=(
                "AI provider to use: deepseek | openrouter | together | "
                "fireworks | gemini. Auto-detected when omitted."
            ),
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            "-m",
            help=(
                "Model name or alias. Examples: qwen3-235b, deepseek-v3, "
                "deepseek-v4-flash, gemini-2.0-flash, deepseek-r1. "
                "Uses the provider's default when omitted."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output the full remediation report as JSON.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write the remediation report to a JSON file.",
        ),
    ] = None,
    findings_file: Annotated[
        Path | None,
        typer.Option(
            "--from-file",
            "-f",
            help=(
                "Read a previously saved 'kasa analyze --json' output instead "
                "of running a fresh collection."
            ),
        ),
    ] = None,
    dashboard_view: Annotated[
        bool,
        typer.Option(
            "--dashboard",
            "-d",
            help="Open the interactive web dashboard with AI findings and attack scenarios.",
        ),
    ] = False,
) -> None:
    """Run AI-powered remediation advice and attack scenario analysis.

    KASA auto-detects your API key from the environment (priority order):
      KASA_API_KEY (universal) → DeepSeek → OpenRouter → Together → Fireworks → Gemini

    Supported model aliases (--model):
      qwen3-235b          → Qwen3-235B-A22B  (via OpenRouter)
      qwen3.6-227b        → Qwen3-235B-A22B  (via OpenRouter)
      deepseek-v3         → DeepSeek-V3       (via DeepSeek API)
      deepseek-v4-flash   → DeepSeek-V3       (latest, via DeepSeek API)
      deepseek-r1         → DeepSeek-R1       (reasoning model)
      gemini-flash        → Gemini 2.0 Flash

    Examples:
      kasa ai                                      # auto-detect everything
      kasa ai --model qwen3-235b                   # use Qwen3 via OpenRouter
      kasa ai --model deepseek-v4-flash --dashboard # run AI and view in web UI
      kasa ai --from-file findings.json --json
    """
    from kasa.ai.client import AIClientError
    from kasa.ai.remediation import RemediationAdvisor
    from kasa.models.risk import RiskAssessment, RiskRating

    # ------------------------------------------------------------------ #
    # 1. Resolve findings + risk                                           #
    # ------------------------------------------------------------------ #
    snapshot_data = None
    if findings_file is not None:
        if not findings_file.exists():
            typer.echo(f"Error: file not found: {findings_file}", err=True)
            raise typer.Exit(1)

        try:
            saved = json.loads(findings_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            typer.echo(f"Error reading findings file: {exc}", err=True)
            raise typer.Exit(1) from exc

        from kasa.models.finding import Finding

        findings = [Finding(**f) for f in saved.get("findings", [])]
        raw_risk = saved.get("risk", {})
        risk = RiskAssessment(
            score=raw_risk.get("score", 0),
            rating=RiskRating(raw_risk.get("rating", "low")),
            finding_count=raw_risk.get("finding_count", len(findings)),
        )
        kernel_release: str | None = saved.get("kernel_release")
        snapshot_data = saved.get("snapshot")
    else:
        typer.echo("Collecting kernel evidence…", err=True)
        from kasa.collectors.system import SystemCollector as _SC

        snapshot = _SC().collect()
        snapshot_data = snapshot.model_dump(mode="json")
        result, risk = _run_analysis()
        findings = result.findings
        kernel_release = snapshot.kernel.kernel.release

    if not findings:
        typer.echo("No security findings to analyse. System appears well-hardened.")
        return

    # ------------------------------------------------------------------ #
    # 2. Build advisor (auto-detects provider + key)                       #
    # ------------------------------------------------------------------ #
    try:
        advisor = RemediationAdvisor(
            provider=provider,
            model=model,
            api_key=api_key,
        )
    except AIClientError as exc:
        typer.echo(f"Error: {exc}", err=True)
        typer.echo("\nRun 'kasa providers' to see available providers.", err=True)
        raise typer.Exit(1) from exc

    typer.echo(
        f"Sending {len(findings)} finding(s) to "
        f"{advisor.provider_name} / {advisor.model}…",
        err=True,
    )

    # ------------------------------------------------------------------ #
    # 3. Call the model                                                    #
    # ------------------------------------------------------------------ #
    try:
        report = advisor.advise(findings, risk, kernel_release)  # type: ignore[arg-type]
    except AIClientError as exc:
        typer.echo(f"AI error: {exc}", err=True)
        raise typer.Exit(1) from exc

    # ------------------------------------------------------------------ #
    # 4. Output                                                            #
    # ------------------------------------------------------------------ #
    report_data = report.model_dump(mode="json", exclude={"raw_response"})

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        typer.echo(f"Remediation report written to: {output}")
        if not dashboard_view:
            return

    if json_output and not dashboard_view:
        typer.echo(json.dumps(report_data, indent=2))
        return

    # Pretty terminal output
    if not json_output:
        typer.echo()
        typer.echo("━" * 66)
        typer.echo(f"  KASA AI Security Analysis  [{advisor.provider_name} / {advisor.model}]")
        typer.echo("━" * 66)
        typer.echo()
        typer.echo(f"Summary: {report.summary}")
        typer.echo()
        typer.echo(f"Risk Assessment: {report.overall_risk_assessment}")
        typer.echo()

        if report.attack_scenarios:
            typer.echo("⚡ Potential Attack Possibilities (Exploit Chains):")
            typer.echo()
            for sc in report.attack_scenarios:
                typer.echo(f"  [{sc.likelihood.upper()}] {sc.name}")
                typer.echo(f"    Impact:    {sc.impact}")
                typer.echo(f"    Access:    {sc.attacker_profile}")
                typer.echo(f"    Details:   {sc.description}")
                if sc.affected_findings:
                    typer.echo(f"    Enabled by: {', '.join(sc.affected_findings)}")
                typer.echo()

        if report.priority_order:
            typer.echo("Priority Order:")
            for i, fid in enumerate(report.priority_order, 1):
                typer.echo(f"  {i}. {fid}")
            typer.echo()

        if report.steps:
            typer.echo("Remediation Steps:")
            typer.echo()
            for step in report.steps:
                typer.echo(f"  [{step.finding_id}]")
                typer.echo(f"  Action:    {step.action}")
                if step.command:
                    typer.echo(f"  Command:   {step.command}")
                typer.echo(f"  Rationale: {step.rationale}")
                typer.echo()

    if dashboard_view:
        typer.echo("\n🚀 Launching Web Dashboard with AI Analysis...")
        initial_data = {
            "snapshot": snapshot_data,
            "findings": [f.model_dump(mode="json") for f in findings],
            "risk": risk.model_dump(mode="json"),
            "ai_report": report_data,
        }
        start_dashboard(initial_data=initial_data, block=True)
