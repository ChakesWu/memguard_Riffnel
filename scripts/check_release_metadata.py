from pathlib import Path
import re

import memguard


PROJECT_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
PROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')


def parse_project_metadata(pyproject_path: Path) -> tuple[str, str]:
    in_project = False
    name = ""
    version = ""

    for raw_line in pyproject_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[project]":
            in_project = True
            continue
        if in_project and line.startswith("["):
            break
        if not in_project:
            continue

        if not name:
            match = PROJECT_NAME_RE.match(line)
            if match:
                name = match.group(1)
                continue

        if not version:
            match = PROJECT_VERSION_RE.match(line)
            if match:
                version = match.group(1)
                continue

    if not name or not version:
        raise SystemExit("Could not parse project metadata from pyproject.toml")

    return name, version


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pyproject_path = repo_root / "pyproject.toml"
    project_name, project_version = parse_project_metadata(pyproject_path)

    if project_name != "memguard-riffnel":
        raise SystemExit(f"Unexpected project name: {project_name}")
    if memguard.__version__ != project_version:
        raise SystemExit(
            f"Version mismatch: pyproject={project_version}, memguard={memguard.__version__}"
        )

    print("metadata_ok")
    print(project_name)
    print(project_version)


if __name__ == "__main__":
    main()
