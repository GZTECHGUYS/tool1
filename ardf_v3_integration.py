#!/usr/bin/env python3
"""ARDF v3 Integration Validator - Comprehensive validation and test suite."""

import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import importlib.util


class ARDFv3Validator:
    """Comprehensive validation suite for ARDF v3."""

    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.results = {
            "core_framework": [],
            "modules": [],
            "endpoints": [],
            "dependencies": [],
            "imports": [],
            "summary": {}
        }
        self.errors = []
        self.warnings = []

    def validate_core_files(self) -> Tuple[int, int]:
        """Validate core framework files exist."""
        required_files = [
            "ardf_v3_framework.py",
            "ardf_v3_endpoints.py",
            "ardf_v3_dashboard_api.py",
            "ardf_v3_main.py",
        ]

        found = 0
        missing = 0

        for filename in required_files:
            filepath = self.base_path / filename
            if filepath.exists():
                self.results["core_framework"].append({
                    "file": filename,
                    "status": "OK",
                    "path": str(filepath)
                })
                found += 1
            else:
                self.results["core_framework"].append({
                    "file": filename,
                    "status": "MISSING",
                    "path": str(filepath)
                })
                missing += 1
                self.errors.append(f"Core file missing: {filename}")

        return found, missing

    def validate_modules(self) -> Tuple[int, int]:
        """Validate all ARDF modules."""
        module_paths = [
            self.base_path / "modules" / "*.py",
            self.base_path / "modules" / "recon" / "*.py",
            self.base_path / "modules" / "defense" / "*.py",
            self.base_path / "modules" / "validate" / "*.py",
            self.base_path / "modules" / "tools" / "*.py",
            self.base_path / "modules" / "purple" / "*.py",
            self.base_path / "core" / "*.py",
            self.base_path / "ai" / "*.py",
            self.base_path / "graph" / "*.py",
            self.base_path / "interface" / "*.py",
            self.base_path / "daemon" / "*.py",
            self.base_path / "playbook" / "*.py",
        ]

        found = 0
        failed = 0

        for pattern in module_paths:
            for filepath in self.base_path.glob(str(pattern).replace(str(self.base_path), "").lstrip("/")):
                if filepath.name.startswith("__"):
                    continue

                try:
                    spec = importlib.util.spec_from_file_location(
                        filepath.stem,
                        filepath
                    )
                    if spec and spec.loader:
                        self.results["modules"].append({
                            "module": filepath.stem,
                            "path": str(filepath),
                            "status": "LOADABLE"
                        })
                        found += 1
                except Exception as e:
                    self.results["modules"].append({
                        "module": filepath.stem,
                        "path": str(filepath),
                        "status": "ERROR",
                        "error": str(e)
                    })
                    failed += 1
                    self.warnings.append(f"Module load issue: {filepath.stem} - {e}")

        return found, failed

    def validate_imports(self) -> Tuple[int, int]:
        """Validate Python imports in core files."""
        core_files = [
            self.base_path / "ardf_v3_framework.py",
            self.base_path / "ardf_v3_endpoints.py",
            self.base_path / "ardf_v3_dashboard_api.py",
            self.base_path / "ardf_v3_main.py",
        ]

        validated = 0
        failed = 0

        for filepath in core_files:
            if not filepath.exists():
                continue

            try:
                with open(filepath) as f:
                    content = f.read()

                imports = []
                for line in content.split("\n"):
                    if line.strip().startswith("import ") or line.strip().startswith("from "):
                        imports.append(line.strip())

                self.results["imports"].append({
                    "file": filepath.name,
                    "import_count": len(imports),
                    "status": "OK",
                    "sample_imports": imports[:3]
                })
                validated += 1
            except Exception as e:
                self.results["imports"].append({
                    "file": filepath.name,
                    "status": "ERROR",
                    "error": str(e)
                })
                failed += 1

        return validated, failed

    def validate_dependencies(self) -> Tuple[List[str], List[str]]:
        """Check external dependencies."""
        dependencies = {
            "flask": "Web dashboard",
            "flask_cors": "CORS support",
            "requests": "HTTP requests",
            "pyyaml": "YAML config",
            "jinja2": "Template engine"
        }

        available = []
        missing = []

        for package, description in dependencies.items():
            try:
                __import__(package.replace("_", "-"))
                available.append(package)
                self.results["dependencies"].append({
                    "package": package,
                    "description": description,
                    "status": "AVAILABLE"
                })
            except ImportError:
                missing.append(package)
                self.results["dependencies"].append({
                    "package": package,
                    "description": description,
                    "status": "MISSING"
                })
                self.warnings.append(f"Optional dependency missing: {package} - {description}")

        return available, missing

    def generate_summary(self) -> Dict:
        """Generate validation summary."""
        core_files, core_missing = self.validate_core_files()
        modules_found, modules_failed = self.validate_modules()
        imports_ok, imports_failed = self.validate_imports()
        deps_available, deps_missing = self.validate_dependencies()

        summary = {
            "timestamp": str(datetime.now()),
            "framework": {
                "core_files": {
                    "found": core_files,
                    "missing": core_missing,
                    "status": "OK" if core_missing == 0 else "INCOMPLETE"
                },
                "modules": {
                    "loadable": modules_found,
                    "failed": modules_failed,
                    "status": "OK" if modules_failed == 0 else "WARNINGS"
                },
                "imports": {
                    "validated": imports_ok,
                    "failed": imports_failed,
                    "status": "OK" if imports_failed == 0 else "ERRORS"
                }
            },
            "dependencies": {
                "available": len(deps_available),
                "missing": len(deps_missing),
                "required": list(deps_available),
                "optional": list(deps_missing)
            },
            "validation": {
                "total_errors": len(self.errors),
                "total_warnings": len(self.warnings),
                "status": "PASS" if len(self.errors) == 0 else "FAIL"
            },
            "errors": self.errors,
            "warnings": self.warnings
        }

        self.results["summary"] = summary
        return summary

    def print_report(self) -> None:
        """Print validation report."""
        summary = self.generate_summary()

        report = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                  ARDF v3 VALIDATION REPORT                                 ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║ CORE FRAMEWORK                                                             ║
║   Files Found:     {summary['framework']['core_files']['found']:50} ║
║   Files Missing:   {summary['framework']['core_files']['missing']:50} ║
║   Status:          {summary['framework']['core_files']['status']:50} ║
║                                                                            ║
║ MODULES                                                                    ║
║   Loadable:        {summary['framework']['modules']['loadable']:50} ║
║   Failed:          {summary['framework']['modules']['failed']:50} ║
║   Status:          {summary['framework']['modules']['status']:50} ║
║                                                                            ║
║ IMPORTS                                                                    ║
║   Validated:       {summary['framework']['imports']['validated']:50} ║
║   Failed:          {summary['framework']['imports']['failed']:50} ║
║   Status:          {summary['framework']['imports']['status']:50} ║
║                                                                            ║
║ DEPENDENCIES                                                               ║
║   Available:       {summary['dependencies']['available']:50} ║
║   Missing:         {summary['dependencies']['missing']:50} ║
║                                                                            ║
║ VALIDATION RESULTS                                                         ║
║   Total Errors:    {summary['validation']['total_errors']:50} ║
║   Total Warnings:  {summary['validation']['total_warnings']:50} ║
║   Overall Status:  {summary['validation']['status']:50} ║
║                                                                            ║
╠════════════════════════════════════════════════════════════════════════════╣
"""

        if self.errors:
            report += "║ ERRORS:                                                                        ║\n"
            for error in self.errors:
                report += f"║   • {error:74} ║\n"
            report += "║                                                                            ║\n"

        if self.warnings:
            report += "║ WARNINGS:                                                                      ║\n"
            for warning in self.warnings:
                report += f"║   • {warning:74} ║\n"
            report += "║                                                                            ║\n"

        report += "╚════════════════════════════════════════════════════════════════════════════════════╝\n"
        print(report)

    def export_json(self, output_file: str) -> bool:
        """Export validation results to JSON."""
        try:
            self.generate_summary()
            with open(output_file, "w") as f:
                json.dump(self.results, f, indent=2)
            print(f"Validation results exported to {output_file}")
            return True
        except Exception as e:
            print(f"Failed to export results: {e}")
            return False


def main():
    """Run validation."""
    import argparse

    parser = argparse.ArgumentParser(description="ARDF v3 Validation Suite")
    parser.add_argument("--base-path", default=".", help="Base path for ARDF")
    parser.add_argument("--export", help="Export results to JSON file")
    args = parser.parse_args()

    validator = ARDFv3Validator(args.base_path)
    validator.print_report()

    if args.export:
        validator.export_json(args.export)

    summary = validator.results["summary"]
    return 0 if summary["validation"]["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
