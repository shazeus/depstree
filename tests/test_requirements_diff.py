from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from depstree.cli import main
from depstree.parsers import scan_project


def test_scan_project_parses_requirements_file(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\nrich>=13\n", encoding="utf-8")

    result = scan_project(requirements)

    assert len(result.manifests) == 1
    assert result.warnings == []
    assert [dependency.name for dependency in result.dependencies(include_transitive=False)] == ["requests", "rich"]


def test_diff_reports_changes_between_requirements_directories(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (before / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (after / "requirements.txt").write_text("requests==2.32.3\nrich>=13\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(before), str(after), "--json-output"])

    assert result.exit_code == 0
    assert '"name": "rich"' in result.output
    assert '"spec": "==2.31.0"' in result.output
    assert '"spec": "==2.32.3"' in result.output
