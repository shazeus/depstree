from __future__ import annotations

import configparser
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from packaging.requirements import InvalidRequirement, Requirement

from .models import Dependency, Manifest, ScanResult

try:  # pragma: no cover - runtime branch depends on Python version
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}

KNOWN_MANIFESTS = {
    "pyproject.toml",
    "setup.cfg",
    "package.json",
    "package-lock.json",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "composer.json",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}


def scan_project(path: str | Path) -> ScanResult:
    root = Path(path).expanduser().resolve()
    scan_root = root.parent if root.is_file() else root
    result = ScanResult(root=scan_root)

    for manifest_path in find_manifest_paths(root):
        try:
            manifest = parse_manifest(manifest_path)
        except Exception as exc:  # noqa: BLE001 - CLI should keep scanning other files
            result.warnings.append(f"{manifest_path}: {exc}")
            continue
        if manifest is not None:
            result.manifests.append(manifest)

    if not result.manifests:
        result.warnings.append(f"No supported dependency manifests found in {root}")
    return result


def find_manifest_paths(root: Path) -> list[Path]:
    if root.is_file():
        return [root]

    found: list[Path] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS and not directory.startswith(".cache")]
        for filename in files:
            if filename in KNOWN_MANIFESTS or _is_requirements_file(filename):
                found.append(Path(current) / filename)
    return sorted(found, key=lambda item: item.as_posix())


def parse_manifest(path: Path) -> Manifest | None:
    filename = path.name
    if filename == "pyproject.toml":
        return parse_pyproject(path)
    if _is_requirements_file(filename):
        return parse_requirements(path)
    if filename == "setup.cfg":
        return parse_setup_cfg(path)
    if filename == "package.json":
        return parse_package_json(path)
    if filename == "package-lock.json":
        return parse_package_lock(path)
    if filename == "Cargo.toml":
        return parse_cargo_toml(path)
    if filename == "Cargo.lock":
        return parse_cargo_lock(path)
    if filename == "go.mod":
        return parse_go_mod(path)
    if filename == "composer.json":
        return parse_composer_json(path)
    if filename == "Gemfile":
        return parse_gemfile(path)
    if filename == "pom.xml":
        return parse_pom_xml(path)
    if filename in {"build.gradle", "build.gradle.kts"}:
        return parse_gradle(path)
    return None


def parse_pyproject(path: Path) -> Manifest:
    data = _load_toml(path)
    manifest = Manifest(path=path, ecosystem="python", kind="pyproject")
    project = data.get("project", {})
    manifest.metadata["project_name"] = project.get("name")
    manifest.metadata["license"] = project.get("license")

    for raw in project.get("dependencies", []) or []:
        _append_requirement(manifest, raw, scope="runtime")

    for extra, requirements in (project.get("optional-dependencies", {}) or {}).items():
        for raw in requirements or []:
            _append_requirement(manifest, raw, scope=f"optional:{extra}", optional=True)

    poetry = data.get("tool", {}).get("poetry", {})
    _append_poetry_dependencies(manifest, poetry.get("dependencies", {}), scope="runtime")
    _append_poetry_dependencies(manifest, poetry.get("dev-dependencies", {}), scope="dev", dev=True)

    for group_name, group in (poetry.get("group", {}) or {}).items():
        _append_poetry_dependencies(
            manifest,
            group.get("dependencies", {}),
            scope=f"group:{group_name}",
            dev=group_name in {"dev", "test", "lint", "docs"},
        )

    return manifest


def parse_requirements(path: Path) -> Manifest:
    manifest = Manifest(path=path, ecosystem="python", kind="requirements")
    scope = _scope_from_filename(path.name)
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r ", "--requirement", "-c ", "--constraint", "--index-url", "--extra-index-url")):
                continue
            dependency = _dependency_from_requirement_line(
                line,
                source=path.as_posix(),
                scope=scope,
                line=line_number,
            )
            if dependency is not None:
                manifest.dependencies.append(dependency)
    return manifest


def parse_setup_cfg(path: Path) -> Manifest:
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    manifest = Manifest(path=path, ecosystem="python", kind="setup.cfg")
    if parser.has_option("metadata", "name"):
        manifest.metadata["project_name"] = parser.get("metadata", "name")
    if parser.has_option("metadata", "license"):
        manifest.metadata["license"] = parser.get("metadata", "license")
    if parser.has_option("options", "install_requires"):
        for raw in _split_multiline(parser.get("options", "install_requires")):
            _append_requirement(manifest, raw, scope="runtime")
    if parser.has_section("options.extras_require"):
        for extra, value in parser.items("options.extras_require"):
            for raw in _split_multiline(value):
                _append_requirement(manifest, raw, scope=f"optional:{extra}", optional=True)
    return manifest


def parse_package_json(path: Path) -> Manifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = Manifest(path=path, ecosystem="npm", kind="package.json")
    manifest.metadata["project_name"] = data.get("name")
    manifest.metadata["license"] = data.get("license")
    dependency_sections = {
        "dependencies": ("runtime", False, False),
        "devDependencies": ("dev", True, False),
        "peerDependencies": ("peer", False, False),
        "optionalDependencies": ("optional", False, True),
        "bundledDependencies": ("bundled", False, False),
        "bundleDependencies": ("bundled", False, False),
    }
    for section, (scope, dev, optional) in dependency_sections.items():
        for name, spec in (data.get(section, {}) or {}).items():
            manifest.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    source=path.as_posix(),
                    scope=scope,
                    spec=str(spec),
                    raw=f"{name}@{spec}",
                    dev=dev,
                    optional=optional,
                )
            )
    return manifest


def parse_package_lock(path: Path) -> Manifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = Manifest(path=path, ecosystem="npm", kind="package-lock")
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, details in packages.items():
            if not package_path or not isinstance(details, dict):
                continue
            name = details.get("name") or _name_from_node_modules_path(package_path)
            if not name:
                continue
            dependencies = details.get("dependencies") if isinstance(details.get("dependencies"), dict) else {}
            manifest.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    source=path.as_posix(),
                    scope="dev" if details.get("dev") else "lock",
                    spec=str(details.get("version", "")),
                    raw=f"{name}@{details.get('version', '')}",
                    dev=bool(details.get("dev")),
                    optional=bool(details.get("optional")),
                    transitive=True,
                    metadata={
                        "license": details.get("license"),
                        "resolved": details.get("resolved"),
                        "requires": list(dependencies),
                    },
                )
            )
    else:
        for name, details in (data.get("dependencies", {}) or {}).items():
            if not isinstance(details, dict):
                continue
            manifest.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    source=path.as_posix(),
                    scope="lock",
                    spec=str(details.get("version", "")),
                    raw=f"{name}@{details.get('version', '')}",
                    dev=bool(details.get("dev")),
                    optional=bool(details.get("optional")),
                    transitive=True,
                    metadata={"requires": list((details.get("requires") or {}).keys())},
                )
            )
    return manifest


def parse_cargo_toml(path: Path) -> Manifest:
    data = _load_toml(path)
    manifest = Manifest(path=path, ecosystem="rust", kind="Cargo.toml")
    package = data.get("package", {})
    manifest.metadata["project_name"] = package.get("name")
    manifest.metadata["license"] = package.get("license")
    _append_cargo_section(manifest, data.get("dependencies", {}), scope="runtime")
    _append_cargo_section(manifest, data.get("dev-dependencies", {}), scope="dev", dev=True)
    _append_cargo_section(manifest, data.get("build-dependencies", {}), scope="build")
    for target, target_data in (data.get("target", {}) or {}).items():
        if isinstance(target_data, dict):
            _append_cargo_section(manifest, target_data.get("dependencies", {}), scope=f"target:{target}")
    return manifest


def parse_cargo_lock(path: Path) -> Manifest:
    data = _load_toml(path)
    manifest = Manifest(path=path, ecosystem="rust", kind="Cargo.lock")
    for package in data.get("package", []) or []:
        requires = []
        for raw_dependency in package.get("dependencies", []) or []:
            requires.append(str(raw_dependency).split(" ", 1)[0])
        manifest.dependencies.append(
            Dependency(
                name=str(package.get("name", "")),
                ecosystem="rust",
                source=path.as_posix(),
                scope="lock",
                spec=str(package.get("version", "")),
                raw=f"{package.get('name', '')} {package.get('version', '')}",
                transitive=True,
                metadata={"checksum": package.get("checksum"), "requires": requires},
            )
        )
    return manifest


def parse_go_mod(path: Path) -> Manifest:
    manifest = Manifest(path=path, ecosystem="go", kind="go.mod")
    in_require_block = False
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("module "):
            manifest.metadata["project_name"] = stripped.split(None, 1)[1]
            continue
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue
        if stripped.startswith("require "):
            content = stripped.removeprefix("require ").strip()
        elif in_require_block:
            content = stripped
        else:
            continue
        indirect = "// indirect" in content
        content = content.split("//", 1)[0].strip()
        parts = content.split()
        if len(parts) >= 2:
            manifest.dependencies.append(
                Dependency(
                    name=parts[0],
                    ecosystem="go",
                    source=path.as_posix(),
                    scope="indirect" if indirect else "runtime",
                    spec=parts[1],
                    raw=content,
                    transitive=indirect,
                    line=line_number,
                )
            )
    return manifest


def parse_composer_json(path: Path) -> Manifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = Manifest(path=path, ecosystem="php", kind="composer.json")
    manifest.metadata["project_name"] = data.get("name")
    manifest.metadata["license"] = data.get("license")
    for section, scope, dev in [("require", "runtime", False), ("require-dev", "dev", True)]:
        for name, spec in (data.get(section, {}) or {}).items():
            manifest.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="php",
                    source=path.as_posix(),
                    scope=scope,
                    spec=str(spec),
                    raw=f"{name}:{spec}",
                    dev=dev,
                )
            )
    return manifest


def parse_gemfile(path: Path) -> Manifest:
    manifest = Manifest(path=path, ecosystem="ruby", kind="Gemfile")
    gem_re = re.compile(r"^\s*gem\s+['\"](?P<name>[^'\"]+)['\"](?P<rest>.*)$")
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = gem_re.match(line)
        if not match:
            continue
        specs = re.findall(r"['\"]([^'\"]+)['\"]", match.group("rest"))
        spec = ", ".join(specs)
        manifest.dependencies.append(
            Dependency(
                name=match.group("name"),
                ecosystem="ruby",
                source=path.as_posix(),
                scope="runtime",
                spec=spec,
                raw=line,
                line=line_number,
            )
        )
    return manifest


def parse_pom_xml(path: Path) -> Manifest:
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    manifest = Manifest(path=path, ecosystem="java", kind="pom.xml")

    def child_text(element: ET.Element, name: str) -> str:
        for child in element:
            if child.tag.endswith(name):
                return (child.text or "").strip()
        return ""

    group = child_text(root, "groupId")
    artifact = child_text(root, "artifactId")
    if artifact:
        manifest.metadata["project_name"] = f"{group}:{artifact}" if group else artifact

    for dependency in root.iter():
        if not dependency.tag.endswith("dependency"):
            continue
        group_id = child_text(dependency, "groupId")
        artifact_id = child_text(dependency, "artifactId")
        version = child_text(dependency, "version")
        scope = child_text(dependency, "scope") or "runtime"
        if group_id and artifact_id:
            manifest.dependencies.append(
                Dependency(
                    name=f"{group_id}:{artifact_id}",
                    ecosystem="java",
                    source=path.as_posix(),
                    scope=scope,
                    spec=version,
                    raw=f"{group_id}:{artifact_id}:{version}",
                    dev=scope == "test",
                )
            )
    return manifest


def parse_gradle(path: Path) -> Manifest:
    manifest = Manifest(path=path, ecosystem="java", kind=path.name)
    text = path.read_text(encoding="utf-8")
    compact_re = re.compile(
        r"(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s+['\"](?P<gav>[^'\"]+)['\"]"
    )
    named_re = re.compile(
        r"(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s+group:\s*['\"](?P<group>[^'\"]+)['\"],\s*name:\s*['\"](?P<name>[^'\"]+)['\"],\s*version:\s*['\"](?P<version>[^'\"]+)['\"]"
    )
    for match in compact_re.finditer(text):
        parts = match.group("gav").split(":")
        if len(parts) >= 2:
            name = ":".join(parts[:2])
            spec = parts[2] if len(parts) > 2 else ""
            scope = match.group("scope")
            manifest.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="java",
                    source=path.as_posix(),
                    scope=scope,
                    spec=spec,
                    raw=match.group(0),
                    dev=scope.startswith("test"),
                )
            )
    for match in named_re.finditer(text):
        scope = match.group("scope")
        manifest.dependencies.append(
            Dependency(
                name=f"{match.group('group')}:{match.group('name')}",
                ecosystem="java",
                source=path.as_posix(),
                scope=scope,
                spec=match.group("version"),
                raw=match.group(0),
                dev=scope.startswith("test"),
            )
        )
    return manifest


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _is_requirements_file(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.startswith("requirements") and lowered.endswith(".txt")


def _scope_from_filename(filename: str) -> str:
    lowered = filename.lower()
    if any(token in lowered for token in ("dev", "test", "lint", "docs")):
        return "dev"
    return "runtime"


def _split_multiline(value: str) -> Iterable[str]:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield stripped


def _append_requirement(
    manifest: Manifest,
    raw: str,
    scope: str,
    optional: bool = False,
    dev: bool = False,
) -> None:
    dependency = _dependency_from_requirement_line(
        raw,
        source=manifest.path.as_posix(),
        scope=scope,
        optional=optional,
        dev=dev,
    )
    if dependency is not None:
        manifest.dependencies.append(dependency)


def _dependency_from_requirement_line(
    line: str,
    source: str,
    scope: str,
    optional: bool = False,
    dev: bool = False,
    line_number: int | None = None,
) -> Dependency | None:
    cleaned = _strip_inline_comment(line)
    if not cleaned:
        return None
    try:
        requirement = Requirement(cleaned)
        name = requirement.name
        spec = str(requirement.specifier)
        if requirement.url:
            spec = requirement.url
        if requirement.marker:
            spec = f"{spec}; {requirement.marker}" if spec else f"; {requirement.marker}"
        return Dependency(
            name=name,
            ecosystem="python",
            source=source,
            scope=scope,
            spec=spec,
            raw=line,
            optional=optional,
            dev=dev or scope == "dev",
            line=line_number,
        )
    except InvalidRequirement:
        name = _name_from_requirement_url(cleaned)
        if not name:
            return None
        return Dependency(
            name=name,
            ecosystem="python",
            source=source,
            scope=scope,
            spec=cleaned,
            raw=line,
            optional=optional,
            dev=dev or scope == "dev",
            line=line_number,
        )


def _strip_inline_comment(line: str) -> str:
    if "#egg=" in line:
        return line.strip()
    return line.split(" #", 1)[0].strip()


def _name_from_requirement_url(value: str) -> str | None:
    egg_match = re.search(r"#egg=([A-Za-z0-9_.-]+)", value)
    if egg_match:
        return egg_match.group(1)
    if "://" in value:
        trimmed = value.rstrip("/").rsplit("/", 1)[-1]
        return trimmed.removesuffix(".git") or None
    return None


def _append_poetry_dependencies(
    manifest: Manifest,
    dependencies: dict[str, Any],
    scope: str,
    dev: bool = False,
) -> None:
    for name, value in (dependencies or {}).items():
        if name.lower() == "python":
            continue
        spec = _poetry_spec(value)
        manifest.dependencies.append(
            Dependency(
                name=name,
                ecosystem="python",
                source=manifest.path.as_posix(),
                scope=scope,
                spec=spec,
                raw=f"{name} {spec}".strip(),
                dev=dev,
                optional=scope.startswith("optional:"),
            )
        )


def _poetry_spec(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = []
        for key in ("version", "git", "path", "url", "branch", "tag", "rev"):
            if key in value:
                parts.append(f"{key}={value[key]}")
        return ", ".join(parts)
    if isinstance(value, list):
        return " | ".join(_poetry_spec(item) for item in value)
    return str(value)


def _append_cargo_section(
    manifest: Manifest,
    dependencies: dict[str, Any],
    scope: str,
    dev: bool = False,
) -> None:
    for name, value in (dependencies or {}).items():
        spec = _cargo_spec(value)
        manifest.dependencies.append(
            Dependency(
                name=name,
                ecosystem="rust",
                source=manifest.path.as_posix(),
                scope=scope,
                spec=spec,
                raw=f"{name} {spec}".strip(),
                dev=dev,
                optional=isinstance(value, dict) and bool(value.get("optional")),
            )
        )


def _cargo_spec(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = []
        for key in ("version", "path", "git", "branch", "tag", "rev", "registry"):
            if key in value:
                parts.append(f"{key}={value[key]}")
        if value.get("optional"):
            parts.append("optional=true")
        return ", ".join(parts)
    return str(value)


def _name_from_node_modules_path(package_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in package_path:
        return None
    tail = package_path.rsplit(marker, 1)[-1]
    parts = tail.split("/")
    if not parts:
        return None
    if parts[0].startswith("@") and len(parts) > 1:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]

