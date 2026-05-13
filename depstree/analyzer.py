from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
import certifi

from .models import Dependency, ScanResult


@dataclass(frozen=True)
class Risk:
    dependency: Dependency
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency": self.dependency.to_dict(),
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }


def summarize(scan: ScanResult) -> dict[str, Any]:
    ecosystems: dict[str, int] = defaultdict(int)
    scopes: dict[str, int] = defaultdict(int)
    for dependency in scan.dependencies():
        ecosystems[dependency.ecosystem] += 1
        scopes[dependency.scope] += 1
    return {
        "manifests": len(scan.manifests),
        "dependencies": len(scan.dependencies()),
        "direct_dependencies": len(scan.dependencies(include_transitive=False)),
        "unique_dependencies": len(scan.unique_dependencies()),
        "ecosystems": dict(sorted(ecosystems.items())),
        "scopes": dict(sorted(scopes.items())),
    }


def audit_dependencies(scan: ScanResult) -> list[Risk]:
    risks: list[Risk] = []
    dependencies = scan.dependencies()
    for dependency in dependencies:
        risks.extend(_dependency_risks(dependency))

    specs_by_identity: dict[str, set[str]] = defaultdict(set)
    deps_by_identity: dict[str, list[Dependency]] = defaultdict(list)
    for dependency in dependencies:
        if dependency.transitive:
            continue
        specs_by_identity[dependency.identity].add(dependency.spec)
        deps_by_identity[dependency.identity].append(dependency)

    for identity, specs in specs_by_identity.items():
        if len(specs) > 1:
            sample = deps_by_identity[identity][0]
            risks.append(
                Risk(
                    dependency=sample,
                    severity="medium",
                    code="duplicate-spec",
                    message=f"{sample.name} is declared with multiple specs: {', '.join(sorted(specs))}",
                )
            )
    return sorted(risks, key=lambda risk: (_severity_rank(risk.severity), risk.dependency.identity, risk.code))


def compare_scans(left: ScanResult, right: ScanResult) -> dict[str, list[dict[str, Any]]]:
    left_deps = _direct_dependency_map(left)
    right_deps = _direct_dependency_map(right)
    left_keys = set(left_deps)
    right_keys = set(right_deps)

    added = [right_deps[key].to_dict() for key in sorted(right_keys - left_keys)]
    removed = [left_deps[key].to_dict() for key in sorted(left_keys - right_keys)]
    changed = []
    for key in sorted(left_keys & right_keys):
        before = left_deps[key]
        after = right_deps[key]
        if before.spec != after.spec or before.scope != after.scope:
            changed.append({"before": before.to_dict(), "after": after.to_dict()})
    return {"added": added, "removed": removed, "changed": changed}


def license_records(scan: ScanResult) -> list[dict[str, Any]]:
    records = []
    for dependency in scan.dependencies():
        license_value = dependency.metadata.get("license") or "unknown"
        records.append(
            {
                "name": dependency.name,
                "ecosystem": dependency.ecosystem,
                "scope": dependency.scope,
                "source": dependency.source,
                "license": license_value,
            }
        )
    return sorted(records, key=lambda item: (item["ecosystem"], item["name"].lower(), item["scope"]))


def explain_dependency(scan: ScanResult, query: str) -> list[Dependency]:
    lowered = query.lower()
    return [
        dependency
        for dependency in scan.dependencies()
        if lowered in dependency.name.lower() or lowered == dependency.normalized_name
    ]


def outdated_records(
    scan: ScanResult,
    ecosystems: set[str] | None = None,
    timeout: float = 4.0,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    checked = 0
    for dependency in scan.dependencies(include_transitive=False):
        if ecosystems and dependency.ecosystem not in ecosystems:
            continue
        if dependency.ecosystem not in {"python", "npm"}:
            continue
        if limit is not None and checked >= limit:
            break
        checked += 1
        current = _current_version_from_spec(dependency.spec, dependency.ecosystem)
        try:
            latest = _latest_version(dependency, timeout=timeout)
            status = _version_status(current, latest)
            error = ""
        except Exception as exc:  # noqa: BLE001 - registry failures should be data, not crashes
            latest = ""
            status = "error"
            error = str(exc)
        records.append(
            {
                "name": dependency.name,
                "ecosystem": dependency.ecosystem,
                "current": current or dependency.spec or "*",
                "latest": latest,
                "status": status,
                "source": dependency.source,
                "error": error,
            }
        )
    return records


def _dependency_risks(dependency: Dependency) -> list[Risk]:
    risks: list[Risk] = []
    spec = dependency.spec.strip()
    raw = dependency.raw.lower()
    if dependency.transitive:
        return risks
    if not spec or spec in {"*", "latest"}:
        risks.append(
            Risk(
                dependency=dependency,
                severity="high",
                code="unpinned",
                message="Dependency has no meaningful version constraint.",
            )
        )
    if re.search(r"(^|[<>=~^,\s])(\*|x)([,\s]|$)", spec.lower()) or "latest" in spec.lower():
        risks.append(
            Risk(
                dependency=dependency,
                severity="high",
                code="wildcard",
                message="Dependency uses a wildcard or latest version.",
            )
        )
    if any(token in raw or token in spec.lower() for token in ("git+", "git=", "github.com", "gitlab.com")):
        risks.append(
            Risk(
                dependency=dependency,
                severity="medium",
                code="git-source",
                message="Dependency resolves from a git or hosted source.",
            )
        )
    if any(token in spec.lower() for token in ("path=", "file:", "../", "./")):
        risks.append(
            Risk(
                dependency=dependency,
                severity="medium",
                code="local-path",
                message="Dependency resolves from a local path.",
            )
        )
    if _looks_like_prerelease(spec):
        risks.append(
            Risk(
                dependency=dependency,
                severity="low",
                code="prerelease",
                message="Dependency appears to allow a prerelease version.",
            )
        )
    if dependency.ecosystem == "python" and spec and not _has_exact_python_pin(spec):
        risks.append(
            Risk(
                dependency=dependency,
                severity="low",
                code="range-spec",
                message="Python dependency is not exactly pinned.",
            )
        )
    if dependency.ecosystem == "npm" and spec and spec[0] in {"^", "~", ">", "<"}:
        risks.append(
            Risk(
                dependency=dependency,
                severity="low",
                code="range-spec",
                message="npm dependency uses a version range.",
            )
        )
    return risks


def _severity_rank(severity: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(severity, 3)


def _direct_dependency_map(scan: ScanResult) -> dict[str, Dependency]:
    result: dict[str, Dependency] = {}
    for dependency in scan.dependencies(include_transitive=False):
        result[dependency.identity] = dependency
    return result


def _looks_like_prerelease(spec: str) -> bool:
    lowered = spec.lower()
    return bool(re.search(r"(\d[0-9.]*[-_.]?(a|b|rc|alpha|beta|pre|dev)\d*)", lowered))


def _has_exact_python_pin(spec: str) -> bool:
    try:
        specifier = SpecifierSet(spec)
    except InvalidSpecifier:
        return False
    return any(item.operator == "==" and "*" not in item.version for item in specifier)


def _current_version_from_spec(spec: str, ecosystem: str) -> str:
    stripped = spec.strip()
    if not stripped:
        return ""
    if ecosystem == "python":
        try:
            specifier = SpecifierSet(stripped)
        except InvalidSpecifier:
            return _first_version_like(stripped)
        exact = [item.version for item in specifier if item.operator == "==" and "*" not in item.version]
        return exact[0] if exact else _first_version_like(stripped)
    if ecosystem == "npm":
        return _first_version_like(stripped.lstrip("^~<>= "))
    return _first_version_like(stripped)


def _first_version_like(value: str) -> str:
    match = re.search(r"\d+(?:\.\d+){0,4}(?:[-+._a-zA-Z0-9]*)?", value)
    return match.group(0) if match else ""


def _latest_version(dependency: Dependency, timeout: float) -> str:
    if dependency.ecosystem == "python":
        url = f"https://pypi.org/pypi/{urllib.parse.quote(dependency.name)}/json"
        payload = _read_json(url, timeout)
        return str(payload["info"]["version"])
    if dependency.ecosystem == "npm":
        quoted = urllib.parse.quote(dependency.name, safe="")
        url = f"https://registry.npmjs.org/{quoted}/latest"
        payload = _read_json(url, timeout)
        return str(payload["version"])
    raise ValueError(f"Unsupported registry ecosystem: {dependency.ecosystem}")


def _read_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "depstree/0.1.0"})
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"registry returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _version_status(current: str, latest: str) -> str:
    if not current:
        return "unknown-current"
    try:
        current_version = Version(current)
        latest_version = Version(latest)
    except InvalidVersion:
        return "unknown-current"
    if current_version < latest_version:
        return "outdated"
    if current_version == latest_version:
        return "current"
    return "ahead"
