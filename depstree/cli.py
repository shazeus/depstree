from __future__ import annotations

import json
from functools import wraps
from pathlib import Path
from typing import Callable, TypeVar

import click
from rich.console import Console

from . import __version__
from .analyzer import audit_dependencies, compare_scans, explain_dependency, license_records, outdated_records
from .exporters import export_graph, export_scan, write_output
from .parsers import scan_project
from .render import print_audit, print_diff, print_explain, print_license_report, print_outdated, print_scan, print_tree

console = Console()
F = TypeVar("F", bound=Callable[..., object])


def handle_errors(func: F) -> F:
    @wraps(func)
    def wrapper(*args: object, **kwargs: object) -> object:
        try:
            return func(*args, **kwargs)
        except click.ClickException:
            raise
        except KeyboardInterrupt as exc:
            raise click.Abort() from exc
        except Exception as exc:  # noqa: BLE001 - render clean CLI errors
            console.print(f"[red]Error:[/] {exc}")
            raise click.Abort() from exc

    return wrapper  # type: ignore[return-value]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="depstree")
def main() -> None:
    """Analyze dependency manifests across common project ecosystems."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--json-output", "json_output", is_flag=True, help="Print machine-readable JSON.")
@handle_errors
def scan(path: Path, json_output: bool) -> None:
    """Detect manifests and summarize dependencies."""
    result = scan_project(path)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
    else:
        print_scan(console, result)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--direct-only", is_flag=True, help="Hide lockfile and transitive dependencies.")
@handle_errors
def tree(path: Path, direct_only: bool) -> None:
    """Render a grouped dependency tree."""
    result = scan_project(path)
    print_tree(console, result, include_transitive=not direct_only)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--strict", is_flag=True, help="Exit with a non-zero status when risks are found.")
@click.option("--json-output", "json_output", is_flag=True, help="Print machine-readable JSON.")
@handle_errors
def audit(path: Path, strict: bool, json_output: bool) -> None:
    """Report risky dependency declarations."""
    result = scan_project(path)
    risks = audit_dependencies(result)
    if json_output:
        console.print_json(json.dumps([risk.to_dict() for risk in risks]))
    else:
        print_audit(console, risks)
    if strict and risks:
        raise click.ClickException(f"{len(risks)} dependency risk(s) found")


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--format", "output_format", type=click.Choice(["table", "json", "csv"]), default="table", show_default=True)
@handle_errors
def licenses(path: Path, output_format: str) -> None:
    """Show dependency license metadata when available."""
    result = scan_project(path)
    records = license_records(result)
    if output_format == "json":
        console.print_json(json.dumps(records))
    elif output_format == "csv":
        columns = ["ecosystem", "name", "scope", "license", "source"]
        console.print(",".join(columns))
        for record in records:
            console.print(",".join(str(record.get(column, "")).replace(",", " ") for column in columns))
    else:
        print_license_report(console, records)


@main.command()
@click.argument("old", type=click.Path(exists=True, path_type=Path))
@click.argument("new", type=click.Path(exists=True, path_type=Path))
@click.option("--json-output", "json_output", is_flag=True, help="Print machine-readable JSON.")
@handle_errors
def diff(old: Path, new: Path, json_output: bool) -> None:
    """Compare dependencies between two projects or manifests."""
    left = scan_project(old)
    right = scan_project(new)
    comparison = compare_scans(left, right)
    if json_output:
        console.print_json(json.dumps(comparison))
    else:
        print_diff(console, comparison)


@main.command(name="export")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--format", "output_format", type=click.Choice(["json", "csv", "sbom", "html"]), default="json", show_default=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Write output to a file instead of stdout.")
@handle_errors
def export_command(path: Path, output_format: str, output: Path | None) -> None:
    """Export dependency data as JSON, CSV, SBOM, or HTML."""
    result = scan_project(path)
    content = export_scan(result, output_format)
    written = write_output(content, output)
    if written:
        console.print(f"[green]Wrote[/] {written}")
    else:
        console.print(content)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--format", "output_format", type=click.Choice(["dot", "svg", "html", "json"]), default="svg", show_default=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Write graph to a file instead of stdout.")
@handle_errors
def graph(path: Path, output_format: str, output: Path | None) -> None:
    """Generate dependency graph output."""
    result = scan_project(path)
    content = export_graph(result, output_format)
    written = write_output(content, output)
    if written:
        console.print(f"[green]Wrote[/] {written}")
    else:
        console.print(content)


@main.command()
@click.argument("package")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@handle_errors
def explain(package: str, path: Path) -> None:
    """Show where a dependency is declared."""
    result = scan_project(path)
    matches = explain_dependency(result, package)
    print_explain(console, matches, package)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--ecosystem", "ecosystems", type=click.Choice(["python", "npm"]), multiple=True, help="Limit checks to an ecosystem.")
@click.option("--timeout", type=float, default=4.0, show_default=True, help="Registry request timeout in seconds.")
@click.option("--limit", type=int, default=None, help="Maximum dependencies to check.")
@click.option("--json-output", "json_output", is_flag=True, help="Print machine-readable JSON.")
@handle_errors
def outdated(path: Path, ecosystems: tuple[str, ...], timeout: float, limit: int | None, json_output: bool) -> None:
    """Check latest versions for Python and npm dependencies."""
    result = scan_project(path)
    records = outdated_records(result, ecosystems=set(ecosystems) or None, timeout=timeout, limit=limit)
    if json_output:
        console.print_json(json.dumps(records))
    else:
        print_outdated(console, records)

