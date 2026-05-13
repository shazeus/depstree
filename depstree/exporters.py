from __future__ import annotations

import csv
import html
import json
from io import StringIO
from pathlib import Path
from typing import Any

from .analyzer import audit_dependencies, license_records, summarize
from .models import Dependency, ScanResult


def export_scan(scan: ScanResult, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(scan.to_dict(), indent=2, sort_keys=True)
    if output_format == "csv":
        return _dependencies_csv(scan.dependencies())
    if output_format == "sbom":
        return json.dumps(_sbom(scan), indent=2, sort_keys=True)
    if output_format == "html":
        return _html_report(scan)
    raise ValueError(f"Unsupported export format: {output_format}")


def export_graph(scan: ScanResult, output_format: str) -> str:
    nodes, edges = _graph(scan)
    if output_format == "json":
        return json.dumps({"nodes": nodes, "edges": edges}, indent=2, sort_keys=True)
    if output_format == "dot":
        return _dot(nodes, edges)
    if output_format == "svg":
        return _svg(nodes, edges)
    if output_format == "html":
        svg = _svg(nodes, edges)
        return (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>Depstree graph</title>"
            "<style>body{font-family:Inter,Arial,sans-serif;margin:24px;background:#f8fafc;color:#111827}"
            "svg{background:white;border:1px solid #e5e7eb;border-radius:8px;max-width:100%;height:auto}</style>"
            "</head><body><h1>Dependency graph</h1>"
            f"{svg}</body></html>"
        )
    raise ValueError(f"Unsupported graph format: {output_format}")


def write_output(content: str, output: str | Path | None) -> Path | None:
    if output is None:
        return None
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _dependencies_csv(dependencies: list[Dependency]) -> str:
    buffer = StringIO()
    fieldnames = [
        "name",
        "ecosystem",
        "scope",
        "spec",
        "source",
        "dev",
        "optional",
        "transitive",
        "via",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for dependency in dependencies:
        row = dependency.to_dict()
        writer.writerow({field: row.get(field, "") for field in fieldnames})
    return buffer.getvalue()


def _sbom(scan: ScanResult) -> dict[str, Any]:
    components = []
    for dependency in scan.dependencies():
        components.append(
            {
                "type": "library",
                "name": dependency.name,
                "version": dependency.spec,
                "scope": dependency.scope,
                "purl": _purl(dependency),
                "properties": [
                    {"name": "depstree:ecosystem", "value": dependency.ecosystem},
                    {"name": "depstree:source", "value": dependency.source},
                    {"name": "depstree:transitive", "value": str(dependency.transitive).lower()},
                ],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tool": {"vendor": "shazeus", "name": "depstree", "version": "0.1.0"}},
        "components": components,
    }


def _purl(dependency: Dependency) -> str:
    namespace = {
        "python": "pypi",
        "npm": "npm",
        "rust": "cargo",
        "go": "golang",
        "java": "maven",
        "ruby": "gem",
        "php": "composer",
    }.get(dependency.ecosystem, dependency.ecosystem)
    name = dependency.name.replace(":", "/") if dependency.ecosystem == "java" else dependency.name
    version = dependency.spec.lstrip("=^~<> ")
    return f"pkg:{namespace}/{name}@{version}" if version else f"pkg:{namespace}/{name}"


def _html_report(scan: ScanResult) -> str:
    summary = summarize(scan)
    risks = audit_dependencies(scan)
    licenses = license_records(scan)
    dep_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(dep.ecosystem)}</td>"
        f"<td>{html.escape(dep.name)}</td>"
        f"<td>{html.escape(dep.scope)}</td>"
        f"<td>{html.escape(dep.display_spec())}</td>"
        f"<td>{html.escape(Path(dep.source).name)}</td>"
        "</tr>"
        for dep in scan.dependencies()
    )
    risk_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(risk.severity)}</td>"
        f"<td>{html.escape(risk.dependency.name)}</td>"
        f"<td>{html.escape(risk.code)}</td>"
        f"<td>{html.escape(risk.message)}</td>"
        "</tr>"
        for risk in risks
    )
    license_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(record['ecosystem'])}</td>"
        f"<td>{html.escape(record['name'])}</td>"
        f"<td>{html.escape(record['license'])}</td>"
        "</tr>"
        for record in licenses
    )
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Depstree report</title>
  <style>
    body {{ font-family: Inter, Arial, sans-serif; margin: 32px; color: #111827; background: #f8fafc; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }}
    .metric {{ background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; margin: 16px 0 28px; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: 9px 10px; text-align: left; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>Depstree report</h1>
  <div class="summary">
    <div class="metric"><strong>{summary['manifests']}</strong><br>Manifests</div>
    <div class="metric"><strong>{summary['dependencies']}</strong><br>Dependencies</div>
    <div class="metric"><strong>{summary['unique_dependencies']}</strong><br>Unique</div>
    <div class="metric"><strong>{len(risks)}</strong><br>Risks</div>
  </div>
  <h2>Dependencies</h2>
  <table><thead><tr><th>Ecosystem</th><th>Name</th><th>Scope</th><th>Spec</th><th>Source</th></tr></thead><tbody>{dep_rows}</tbody></table>
  <h2>Audit findings</h2>
  <table><thead><tr><th>Severity</th><th>Package</th><th>Code</th><th>Message</th></tr></thead><tbody>{risk_rows}</tbody></table>
  <h2>Licenses</h2>
  <table><thead><tr><th>Ecosystem</th><th>Name</th><th>License</th></tr></thead><tbody>{license_rows}</tbody></table>
</body>
</html>
"""


def _graph(scan: ScanResult) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = [{"id": "root", "label": scan.root.name or scan.root.as_posix(), "kind": "root"}]
    edges: list[dict[str, Any]] = []
    seen_nodes = {"root"}
    for manifest_index, manifest in enumerate(scan.manifests):
        manifest_id = f"manifest:{manifest_index}"
        nodes.append({"id": manifest_id, "label": manifest.path.name, "kind": "manifest", "ecosystem": manifest.ecosystem})
        edges.append({"from": "root", "to": manifest_id, "label": manifest.ecosystem})
        seen_nodes.add(manifest_id)
        for dependency in manifest.dependencies:
            dep_id = f"dep:{dependency.identity}"
            if dep_id not in seen_nodes:
                nodes.append(
                    {
                        "id": dep_id,
                        "label": dependency.name,
                        "kind": "dependency",
                        "ecosystem": dependency.ecosystem,
                        "scope": dependency.scope,
                    }
                )
                seen_nodes.add(dep_id)
            edges.append({"from": manifest_id, "to": dep_id, "label": dependency.scope})
    return nodes, edges


def _dot(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    lines = ["digraph depstree {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
    for node in nodes:
        lines.append(f'  "{_dot_escape(node["id"])}" [label="{_dot_escape(node["label"])}"];')
    for edge in edges:
        lines.append(
            f'  "{_dot_escape(edge["from"])}" -> "{_dot_escape(edge["to"])}" [label="{_dot_escape(edge["label"])}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _dot_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _svg(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    positions: dict[str, tuple[int, int]] = {}
    root_nodes = [node for node in nodes if node["kind"] == "root"]
    manifest_nodes = [node for node in nodes if node["kind"] == "manifest"]
    dep_nodes = [node for node in nodes if node["kind"] == "dependency"]

    y = 40
    for node in root_nodes:
        positions[node["id"]] = (40, y)
        y += 90
    y = 40
    for node in manifest_nodes:
        positions[node["id"]] = (300, y)
        y += 70
    y = 40
    for node in dep_nodes:
        positions[node["id"]] = (620, y)
        y += 46

    height = max(220, y + 40, len(manifest_nodes) * 70 + 80)
    width = 980
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<defs><style>.node{fill:#ffffff;stroke:#d1d5db;stroke-width:1.2}.root{fill:#111827}.rootText{fill:#ffffff}.edge{stroke:#9ca3af;stroke-width:1.2}.label{font:12px Arial,sans-serif;fill:#374151}.small{font:10px Arial,sans-serif;fill:#6b7280}</style></defs>',
    ]
    for edge in edges:
        start = positions.get(edge["from"])
        end = positions.get(edge["to"])
        if not start or not end:
            continue
        lines.append(f'<line class="edge" x1="{start[0] + 180}" y1="{start[1] + 18}" x2="{end[0]}" y2="{end[1] + 18}"/>')
    for node in nodes:
        x, node_y = positions[node["id"]]
        label = html.escape(str(node["label"]))
        kind = node["kind"]
        width_px = 190 if kind != "dependency" else 300
        css_class = "node root" if kind == "root" else "node"
        text_class = "label rootText" if kind == "root" else "label"
        lines.append(f'<rect class="{css_class}" x="{x}" y="{node_y}" rx="7" ry="7" width="{width_px}" height="36"/>')
        lines.append(f'<text class="{text_class}" x="{x + 12}" y="{node_y + 23}">{label}</text>')
        if kind == "dependency":
            meta = html.escape(str(node.get("scope", "")))
            lines.append(f'<text class="small" x="{x + 210}" y="{node_y + 23}">{meta}</text>')
    lines.append("</svg>")
    return "\n".join(lines)

