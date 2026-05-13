from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name


@dataclass(frozen=True)
class Dependency:
    name: str
    ecosystem: str
    source: str
    scope: str = "runtime"
    spec: str = ""
    raw: str = ""
    optional: bool = False
    dev: bool = False
    transitive: bool = False
    via: str | None = None
    line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_name(self) -> str:
        if self.ecosystem in {"python", "npm"}:
            return canonicalize_name(self.name)
        return self.name.lower()

    @property
    def identity(self) -> str:
        return f"{self.ecosystem}:{self.normalized_name}"

    def display_spec(self) -> str:
        return self.spec or "*"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "source": self.source,
            "scope": self.scope,
            "spec": self.spec,
            "raw": self.raw,
            "optional": self.optional,
            "dev": self.dev,
            "transitive": self.transitive,
            "via": self.via,
            "line": self.line,
            "metadata": self.metadata,
        }


@dataclass
class Manifest:
    path: Path
    ecosystem: str
    kind: str
    dependencies: list[Dependency] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def relative_path(self, root: Path) -> str:
        try:
            return self.path.relative_to(root).as_posix()
        except ValueError:
            return self.path.as_posix()

    def to_dict(self, root: Path) -> dict[str, Any]:
        return {
            "path": self.relative_path(root),
            "ecosystem": self.ecosystem,
            "kind": self.kind,
            "metadata": self.metadata,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }


@dataclass
class ScanResult:
    root: Path
    manifests: list[Manifest] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def dependencies(self, include_transitive: bool = True) -> list[Dependency]:
        deps: list[Dependency] = []
        for manifest in self.manifests:
            for dependency in manifest.dependencies:
                if include_transitive or not dependency.transitive:
                    deps.append(dependency)
        return deps

    def unique_dependencies(self, include_transitive: bool = True) -> dict[str, Dependency]:
        unique: dict[str, Dependency] = {}
        for dependency in self.dependencies(include_transitive=include_transitive):
            unique.setdefault(dependency.identity, dependency)
        return unique

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root.as_posix(),
            "manifests": [manifest.to_dict(self.root) for manifest in self.manifests],
            "warnings": self.warnings,
            "totals": {
                "manifests": len(self.manifests),
                "dependencies": len(self.dependencies()),
                "direct_dependencies": len(self.dependencies(include_transitive=False)),
                "unique_dependencies": len(self.unique_dependencies()),
            },
        }

