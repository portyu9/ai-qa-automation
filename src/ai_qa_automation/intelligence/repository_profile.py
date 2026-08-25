from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..fs_observation import scan_regular_files_confined


@dataclass(frozen=True)
class RepositoryProfile:
    languages: tuple[str, ...]
    test_surfaces: tuple[str, ...]
    architecture_surfaces: tuple[str, ...]
    ci_surfaces: tuple[str, ...]
    notable_files: tuple[str, ...]
    scanned_files: int
    truncated: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "languages": list(self.languages),
            "test_surfaces": list(self.test_surfaces),
            "architecture_surfaces": list(self.architecture_surfaces),
            "ci_surfaces": list(self.ci_surfaces),
            "notable_files": list(self.notable_files),
            "scanned_files": self.scanned_files,
            "truncated": self.truncated,
        }


class RepositoryProfiler:
    """Bounded path-level repository profiler; it never executes SUT code."""

    _EXTENSIONS: ClassVar[dict[str, str]] = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".java": "java",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".cs": "csharp",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".swift": "swift",
        ".dart": "dart",
    }

    def profile(
        self,
        workspace: Path,
        *,
        max_files: int = 20_000,
        max_scan_entries: int = 20_000,
    ) -> RepositoryProfile:
        for name, value in {
            "max_files": max_files,
            "max_scan_entries": max_scan_entries,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        workspace = workspace.expanduser().absolute()
        ignored = {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "dist",
            "build",
            ".tox",
            ".gradle",
            "target",
        }
        languages: Counter[str] = Counter()
        tests: set[str] = set()
        architecture: set[str] = set()
        ci: set[str] = set()
        notable: set[str] = set()

        scan = scan_regular_files_confined(
            workspace,
            max_entries=max_scan_entries,
            ignored_names=ignored,
            label="repository profile scan",
        )
        truncated = scan.truncated or bool(scan.unsafe_paths or scan.unreadable_paths)
        scanned_files = 0

        for observed in scan.files:
            if scanned_files >= max_files:
                truncated = True
                break
            scanned_files += 1
            relative = observed.path
            lower = relative.as_posix().casefold()
            name = relative.name.casefold()
            language = self._EXTENSIONS.get(relative.suffix.casefold())
            if language:
                languages[language] += 1

            if "pytest" in lower or name in {"conftest.py", "pytest.ini"}:
                tests.add("pytest")
            if "playwright" in lower:
                tests.add("playwright")
            if "cypress" in lower:
                tests.add("cypress")
            if "selenium" in lower:
                tests.add("selenium")
            if "appium" in lower:
                tests.add("appium")
            if "k6" in lower or lower.endswith(".k6.js"):
                tests.add("k6")
            if "jmeter" in lower or lower.endswith(".jmx"):
                tests.add("jmeter")
            if "postman" in lower:
                tests.add("postman")

            if name in {
                "openapi.yaml",
                "openapi.yml",
                "openapi.json",
                "swagger.yaml",
                "swagger.json",
            }:
                architecture.add("api-contract")
                notable.add(relative.as_posix())
            if relative.suffix.casefold() == ".proto":
                architecture.add("protobuf")
            if "graphql" in lower or relative.suffix.casefold() == ".graphql":
                architecture.add("graphql")
            if any(part.casefold() in {"migrations", "migration"} for part in relative.parts):
                architecture.add("database-migrations")
            if name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
                architecture.add("containers")
                notable.add(relative.as_posix())
            if relative.suffix.casefold() == ".tf":
                architecture.add("terraform")
            if any(token in lower for token in ("kubernetes", "k8s/", "helm/", "chart.yaml")):
                architecture.add("kubernetes")
            if any(token in lower for token in ("android", "ios/", "xcodeproj", "gradle")):
                architecture.add("mobile")

            if lower.startswith(".github/workflows/"):
                ci.add("github-actions")
                notable.add(relative.as_posix())
            elif "jenkinsfile" in name:
                ci.add("jenkins")
            elif name == "azure-pipelines.yml":
                ci.add("azure-pipelines")
            elif name == ".gitlab-ci.yml":
                ci.add("gitlab-ci")

        ordered_languages = tuple(name for name, _ in languages.most_common(12))
        return RepositoryProfile(
            languages=ordered_languages,
            test_surfaces=tuple(sorted(tests)),
            architecture_surfaces=tuple(sorted(architecture)),
            ci_surfaces=tuple(sorted(ci)),
            notable_files=tuple(sorted(notable)[:100]),
            scanned_files=scanned_files,
            truncated=truncated,
        )
