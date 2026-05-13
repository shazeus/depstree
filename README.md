<p align="center">
  <h1 align="center">Depstree</h1>
  <p align="center">Dependency analyzer for any project.</p>
  <p align="center">
    <a href="https://pypi.org/project/depstree/"><img alt="PyPI" src="https://img.shields.io/pypi/v/depstree.svg"></a>
    <a href="https://pypi.org/project/depstree/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/depstree.svg"></a>
    <a href="https://github.com/shazeus/depstree/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/shazeus/depstree.svg"></a>
    <a href="https://github.com/shazeus/depstree"><img alt="Stars" src="https://img.shields.io/github/stars/shazeus/depstree.svg?style=social"></a>
  </p>
</p>

---

Depstree scans real project manifests, normalizes dependencies across ecosystems, and turns them into readable terminal reports, dependency trees, audits, diffs, exports, and graph artifacts. It supports Python, Node.js, Rust, Go, Java Maven/Gradle, Ruby, and PHP projects without requiring the target project to install anything first.

- **Multi-ecosystem scanning** - detects `pyproject.toml`, `requirements*.txt`, `package.json`, `Cargo.toml`, `go.mod`, `pom.xml`, `Gemfile`, `composer.json`, and more.
- **Readable dependency trees** - renders grouped runtime, dev, optional, peer, build, and transitive dependency views with Rich.
- **Risk audits** - flags unpinned versions, wildcard specs, local path dependencies, git/url dependencies, duplicate specs, and prerelease usage.
- **Project diffs** - compares two directories or manifests and shows added, removed, and changed dependencies.
- **Portable exports** - writes JSON, CSV, CycloneDX-style SBOM, HTML reports, DOT, SVG, and graph JSON.
- **Registry checks** - checks latest versions for Python and npm dependencies when network access is available.

## Installation

```bash
pip install depstree
```

For local development:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Usage

Scan the current project:

```bash
depstree scan .
```

Print a dependency tree:

```bash
depstree tree .
```

Audit for risky dependency declarations:

```bash
depstree audit . --strict
```

Export an SBOM:

```bash
depstree export . --format sbom --output sbom.json
```

Create an SVG graph:

```bash
depstree graph . --format svg --output deps.svg
```

Compare two project states:

```bash
depstree diff ./before ./after
```

## Commands

| Command | Description |
| --- | --- |
| `depstree scan <path>` | Detect manifests and summarize dependencies. |
| `depstree tree <path>` | Render a grouped dependency tree. |
| `depstree audit <path>` | Report risky specs and duplicate declarations. |
| `depstree licenses <path>` | Show dependency license metadata when manifests or lockfiles expose it. |
| `depstree diff <old> <new>` | Compare two projects or manifests. |
| `depstree export <path>` | Export dependency data as JSON, CSV, SBOM, or HTML. |
| `depstree graph <path>` | Generate DOT, SVG, HTML, or JSON graph output. |
| `depstree explain <package> <path>` | Show where a dependency is declared and under which scope. |
| `depstree outdated <path>` | Check latest registry versions for Python and npm packages. |

## Configuration

Depstree works without a config file. It skips noisy generated directories such as `.git`, `.venv`, `node_modules`, `dist`, `build`, and `target`. Use command options to choose export formats, include or hide transitive dependencies, filter outdated checks by ecosystem, or make audits fail CI with `--strict`.

## License

MIT License. See [LICENSE](LICENSE).

