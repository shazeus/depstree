from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .analyzer import Risk, summarize
from .models import Dependency, ScanResult


def print_scan(console: Console, scan: ScanResult) -> None:
    summary = summarize(scan)
    table = Table(title="Depstree scan", show_header=True, header_style="bold cyan")
    table.add_column("Ecosystem")
    table.add_column("Manifest")
    table.add_column("Direct", justify="right")
    table.add_column("Transitive", justify="right")
    table.add_column("Total", justify="right")

    for manifest in scan.manifests:
        direct = sum(1 for dep in manifest.dependencies if not dep.transitive)
        transitive = sum(1 for dep in manifest.dependencies if dep.transitive)
        table.add_row(
            manifest.ecosystem,
            manifest.relative_path(scan.root),
            str(direct),
            str(transitive),
            str(len(manifest.dependencies)),
        )
    console.print(table)
    console.print(
        Panel(
            f"Manifests: [bold]{summary['manifests']}[/]  "
            f"Dependencies: [bold]{summary['dependencies']}[/]  "
            f"Unique: [bold]{summary['unique_dependencies']}[/]",
            title="Summary",
            border_style="green",
        )
    )
    _print_warnings(console, scan)


def print_tree(console: Console, scan: ScanResult, include_transitive: bool = True) -> None:
    root_label = f"{scan.root.name or scan.root.as_posix()} ({len(scan.manifests)} manifests)"
    tree = Tree(f"[bold green]{root_label}[/]")
    for manifest in scan.manifests:
        manifest_branch = tree.add(f"[bold cyan]{manifest.relative_path(scan.root)}[/] [dim]{manifest.ecosystem}[/]")
        grouped: dict[str, list[Dependency]] = {}
        for dependency in manifest.dependencies:
            if include_transitive or not dependency.transitive:
                grouped.setdefault(dependency.scope, []).append(dependency)
        for scope, dependencies in sorted(grouped.items()):
            scope_branch = manifest_branch.add(f"[magenta]{scope}[/] [dim]{len(dependencies)}[/]")
            for dependency in sorted(dependencies, key=lambda dep: dep.name.lower()):
                flags = []
                if dependency.dev:
                    flags.append("dev")
                if dependency.optional:
                    flags.append("optional")
                if dependency.transitive:
                    flags.append("transitive")
                suffix = f" [dim]({', '.join(flags)})[/]" if flags else ""
                scope_branch.add(f"{dependency.name} [dim]{dependency.display_spec()}[/]{suffix}")
    console.print(tree)
    _print_warnings(console, scan)


def print_audit(console: Console, risks: list[Risk]) -> None:
    table = Table(title="Dependency audit", show_header=True, header_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Package")
    table.add_column("Code")
    table.add_column("Message")
    table.add_column("Source")
    for risk in risks:
        style = {"high": "red", "medium": "yellow", "low": "blue"}.get(risk.severity, "white")
        table.add_row(
            f"[{style}]{risk.severity}[/]",
            risk.dependency.name,
            risk.code,
            risk.message,
            Path(risk.dependency.source).name,
        )
    if risks:
        console.print(table)
    else:
        console.print(Panel("No dependency risks found.", border_style="green"))


def print_diff(console: Console, diff: dict[str, list[dict]]) -> None:
    table = Table(title="Dependency diff", show_header=True, header_style="bold cyan")
    table.add_column("Change")
    table.add_column("Package")
    table.add_column("Before")
    table.add_column("After")
    for item in diff["added"]:
        table.add_row("[green]added[/]", f"{item['ecosystem']}:{item['name']}", "", item.get("spec") or "*")
    for item in diff["removed"]:
        table.add_row("[red]removed[/]", f"{item['ecosystem']}:{item['name']}", item.get("spec") or "*", "")
    for item in diff["changed"]:
        before = item["before"]
        after = item["after"]
        table.add_row(
            "[yellow]changed[/]",
            f"{after['ecosystem']}:{after['name']}",
            before.get("spec") or "*",
            after.get("spec") or "*",
        )
    if any(diff.values()):
        console.print(table)
    else:
        console.print(Panel("No dependency changes found.", border_style="green"))


def print_license_report(console: Console, records: list[dict]) -> None:
    table = Table(title="Dependency licenses", show_header=True, header_style="bold cyan")
    table.add_column("Ecosystem")
    table.add_column("Package")
    table.add_column("Scope")
    table.add_column("License")
    for record in records:
        table.add_row(record["ecosystem"], record["name"], record["scope"], record["license"])
    console.print(table)


def print_explain(console: Console, matches: list[Dependency], query: str) -> None:
    if not matches:
        console.print(Panel(f"No dependency matched '{query}'.", border_style="yellow"))
        return
    table = Table(title=f"Why {query} is present", show_header=True, header_style="bold cyan")
    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Scope")
    table.add_column("Spec")
    table.add_column("Source")
    table.add_column("Line", justify="right")
    for dependency in matches:
        table.add_row(
            dependency.name,
            dependency.ecosystem,
            dependency.scope,
            dependency.display_spec(),
            dependency.source,
            str(dependency.line or ""),
        )
    console.print(table)


def print_outdated(console: Console, records: list[dict]) -> None:
    table = Table(title="Registry version check", show_header=True, header_style="bold cyan")
    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Current")
    table.add_column("Latest")
    table.add_column("Status")
    table.add_column("Error")
    for record in records:
        status = record["status"]
        style = {"outdated": "yellow", "current": "green", "error": "red"}.get(status, "blue")
        table.add_row(
            record["name"],
            record["ecosystem"],
            record["current"],
            record["latest"],
            f"[{style}]{status}[/]",
            record["error"],
        )
    if records:
        console.print(table)
    else:
        console.print(Panel("No Python or npm dependencies were eligible for registry checks.", border_style="yellow"))


def _print_warnings(console: Console, scan: ScanResult) -> None:
    if scan.warnings:
        console.print(Panel("\n".join(scan.warnings), title="Warnings", border_style="yellow"))

