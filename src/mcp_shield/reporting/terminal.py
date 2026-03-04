"""Rich terminal reporter — renders check results as coloured tables."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_shield.reporting.recommendations import generate_recommendations, render_recommendations
from mcp_shield.reporting.score import compute_score, grade_label
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport, sort_results

_OUTCOME_STYLE = {
    Outcome.PASS: "green",
    Outcome.FAIL: "red bold",
    Outcome.WARN: "yellow",
    Outcome.SKIP: "dim",
    Outcome.ERROR: "red",
}

_OUTCOME_SYMBOL = {
    Outcome.PASS: "PASS",
    Outcome.FAIL: "FAIL",
    Outcome.WARN: "WARN",
    Outcome.SKIP: "SKIP",
    Outcome.ERROR: "ERR ",
}


def _render_critical_issues(
    results: list[CheckResult], console: Console
) -> None:
    """Render a prominent alert panel for all FAIL/ERROR outcomes."""
    critical = [
        r for r in results
        if r.outcome in (Outcome.FAIL, Outcome.ERROR)
    ]
    if not critical:
        return

    lines: list[Text] = []
    for r in critical:
        symbol = _OUTCOME_SYMBOL.get(r.outcome, "?")
        line = Text()
        line.append(f"  {r.check_id} ", style="bold")
        line.append(f"{symbol}  ", style=_OUTCOME_STYLE.get(r.outcome, ""))
        line.append(r.message)
        lines.append(line)

        if r.details:
            for d in r.details[:5]:
                detail_line = Text(f"    {d.strip()}", style="red")
                lines.append(detail_line)
            if len(r.details) > 5:
                lines.append(Text(f"    ... and {len(r.details) - 5} more", style="dim"))

    body = Text("\n").join(lines)
    console.print(Panel(
        body,
        title="Critical Issues",
        border_style="red bold",
        padding=(1, 2),
    ))
    console.print()


def render(report: SuiteReport, console: Console | None = None) -> None:
    """Print the suite report to the terminal."""
    console = console or Console()

    # Header
    title_parts = ["MCP Shield Report"]
    if report.server_name:
        title_parts.append(f"  {report.server_name}")
        if report.server_version:
            title_parts.append(f"v{report.server_version}")
    console.print()
    console.rule(" ".join(title_parts))
    console.print()

    # Critical issues alert — shown before the table
    _render_critical_issues(report.results, console)

    # Results table
    sorted_results = sort_results(report.results)

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Check", min_width=12)
    table.add_column("Result", width=6, justify="center")
    table.add_column("Severity", width=10)
    table.add_column("Message")
    table.add_column("Time", width=8, justify="right")

    for r in sorted_results:
        style = _OUTCOME_STYLE.get(r.outcome, "")
        symbol = _OUTCOME_SYMBOL.get(r.outcome, "?")
        result_text = Text(symbol, style=style)
        time_str = f"{r.duration_ms}ms" if r.duration_ms else ""

        table.add_row(r.check_id, result_text, r.severity, r.message, time_str)

        # Show details on failure/warning — use severity-aware style
        if r.details and r.outcome in (Outcome.FAIL, Outcome.WARN, Outcome.ERROR):
            detail_style = "red dim" if r.outcome == Outcome.FAIL else "dim"
            for detail in r.details:
                table.add_row("", "", "", Text(detail, style=detail_style), "")

    console.print(table)
    console.print()

    # Score panel
    score = compute_score(report)
    grade = grade_label(score)

    if score >= 80:
        score_style = "green bold"
    elif score >= 60:
        score_style = "yellow bold"
    else:
        score_style = "red bold"

    summary_lines = [
        f"Score: {score:.0f}/100  Grade: {grade}",
        f"Checks: {report.total_checks}  "
        f"Passed: {report.passed}  "
        f"Failed: {report.failed}  "
        f"Warnings: {report.warnings}  "
        f"Skipped: {report.skipped}",
        f"Duration: {report.duration_ms}ms",
    ]

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="Summary",
            border_style=score_style,
        )
    )
    console.print()

    # Recommendations
    recs = generate_recommendations(report)
    render_recommendations(recs, console)
