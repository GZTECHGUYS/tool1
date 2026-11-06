#!/usr/bin/env python3
"""ARDF V3 Framework - Complete unified orchestrator for all ARDF v2 components."""

import sys
import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "3.0.0"


@dataclass
class ModuleMetadata:
    """Module metadata for registration and discovery."""
    name: str
    category: str
    version: str
    path: str
    exports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    status: str = "uninitialized"
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class EndpointDefinition:
    """Endpoint definition for API mapping."""
    path: str
    method: str
    handler: Callable
    category: str
    requires_auth: bool = False
    doc: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)


class ModuleDiscovery:
    """Auto-discovery system for ARDF modules."""

    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.discovered = {}
        self.logger = logging.getLogger("ModuleDiscovery")

    def discover(self) -> Dict[str, ModuleMetadata]:
        """Discover all ARDF modules in the codebase."""
        categories = {
            "core": self.base_path.glob("*.py"),
            "modules": self.base_path.glob("modules/*.py"),
            "recon": self.base_path.glob("modules/recon/*.py"),
            "defense": self.base_path.glob("modules/defense/*.py"),
            "validate": self.base_path.glob("modules/validate/*.py"),
            "tools": self.base_path.glob("modules/tools/*.py"),
            "purple": self.base_path.glob("modules/purple/*.py"),
            "ai": self.base_path.glob("ai/*.py"),
            "graph": self.base_path.glob("graph/*.py"),
            "core_pkg": self.base_path.glob("core/*.py"),
            "interface": self.base_path.glob("interface/*.py"),
            "daemon": self.base_path.glob("daemon/*.py"),
            "playbook": self.base_path.glob("playbook/*.py"),
        }

        for category, files in categories.items():
            for filepath in files:
                if filepath.name.startswith("__"):
                    continue
                module_name = filepath.stem
                metadata = ModuleMetadata(
                    name=module_name,
                    category=category,
                    version="2.0.0",
                    path=str(filepath),
                    exports=[],
                    dependencies=[]
                )
                self.discovered[f"{category}.{module_name}"] = metadata

        self.logger.info(f"Discovered {len(self.discovered)} modules")
        return self.discovered


class EndpointRegistry:
    """Dynamic endpoint registry for API and CLI."""

    def __init__(self):
        self.endpoints: Dict[str, EndpointDefinition] = {}
        self.categories: Dict[str, List[str]] = {}
        self.logger = logging.getLogger("EndpointRegistry")

    def register(self, endpoint: EndpointDefinition) -> None:
        """Register an endpoint."""
        key = f"{endpoint.method} {endpoint.path}"
        self.endpoints[key] = endpoint

        if endpoint.category not in self.categories:
            self.categories[endpoint.category] = []
        self.categories[endpoint.category].append(key)

        self.logger.debug(f"Registered endpoint: {key}")

    def get_endpoint(self, path: str, method: str = "GET") -> Optional[EndpointDefinition]:
        """Get endpoint by path and method."""
        key = f"{method} {path}"
        return self.endpoints.get(key)

    def list_endpoints(self, category: Optional[str] = None) -> Dict[str, Any]:
        """List all registered endpoints, optionally filtered by category."""
        result = {}
        for key, endpoint in self.endpoints.items():
            if category and endpoint.category != category:
                continue
            result[key] = {
                "path": endpoint.path,
                "method": endpoint.method,
                "category": endpoint.category,
                "requires_auth": endpoint.requires_auth,
                "doc": endpoint.doc,
                "parameters": endpoint.parameters
            }
        return result

    def get_categories(self) -> Dict[str, List[str]]:
        """Get all endpoint categories."""
        return self.categories


class ARDFv3Framework:
    """Main ARDF v3 Framework orchestrator."""

    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.logger = self._setup_logging()
        self.modules = {}
        self.endpoints = EndpointRegistry()
        self.discovery = ModuleDiscovery(str(self.base_path))
        self.executor = ThreadPoolExecutor(max_workers=8)
        self.state = {
            "initialized": False,
            "modules_loaded": 0,
            "modules_failed": 0,
            "endpoints_registered": 0,
            "start_time": datetime.now().isoformat()
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging."""
        logger = logging.getLogger("ARDFv3")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def discover_modules(self) -> Dict[str, ModuleMetadata]:
        """Discover all available modules."""
        self.logger.info("Starting module discovery...")
        discovered = self.discovery.discover()
        self.logger.info(f"Found {len(discovered)} modules")
        return discovered

    def load_module(self, module_path: str) -> bool:
        """Load a single module.

        Each file is executed under a unique synthetic name. Bare stems
        (``logger``, ``ardf``) used to collide with real package modules and
        could deadlock CPython's import lock when several loads ran at once.
        """
        try:
            parts = module_path.split(".")
            if len(parts) == 2:
                category, module_name = parts
            else:
                module_name = parts[-1]
                category = "unknown"

            unique_name = f"_ardf_discovered_{category}_{module_name}"
            spec = importlib.util.spec_from_file_location(
                unique_name,
                self.base_path / self.discovery.discovered[module_path].path
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.modules[module_path] = module
                self.discovery.discovered[module_path].status = "loaded"
                self.state["modules_loaded"] += 1
                self.logger.debug(f"Loaded module: {module_path}")
                return True
        except Exception as e:
            self.discovery.discovered[module_path].status = "failed"
            self.discovery.discovered[module_path].error = str(e)
            self.state["modules_failed"] += 1
            self.logger.warning(f"Failed to load {module_path}: {e}")
            return False

    def load_all_modules(self) -> Dict[str, bool]:
        """Load all discovered modules sequentially.

        The previous ThreadPoolExecutor version imported 190+ files at the
        same time and produced ``deadlock detected by _ModuleLock`` warnings
        for ``modules.logger`` / ``modules.exploit``. Module import is not a
        thread-safe free-for-all; serial loading is deterministic and still
        completes in a few seconds.
        """
        self.logger.info("Loading all discovered modules...")
        results = {}

        discovered = self.discover_modules()
        for module_path in discovered.keys():
            try:
                results[module_path] = self.load_module(module_path)
            except Exception as e:
                self.logger.error(f"Exception loading {module_path}: {e}")
                results[module_path] = False

        self.logger.info(f"Module loading complete: {self.state['modules_loaded']} loaded, {self.state['modules_failed']} failed")
        return results

    def register_core_endpoints(self) -> None:
        """Register core framework endpoints."""
        endpoints = [
            EndpointDefinition(
                path="/api/v3/health",
                method="GET",
                handler=self.health_check,
                category="system",
                doc="Framework health check"
            ),
            EndpointDefinition(
                path="/api/v3/modules",
                method="GET",
                handler=self.get_modules,
                category="system",
                doc="List all loaded modules"
            ),
            EndpointDefinition(
                path="/api/v3/modules/{module}",
                method="GET",
                handler=self.get_module_info,
                category="system",
                doc="Get specific module information"
            ),
            EndpointDefinition(
                path="/api/v3/endpoints",
                method="GET",
                handler=self.list_endpoints,
                category="system",
                doc="List all registered endpoints"
            ),
            EndpointDefinition(
                path="/api/v3/endpoints/{category}",
                method="GET",
                handler=self.list_endpoints_by_category,
                category="system",
                doc="List endpoints by category"
            ),
            EndpointDefinition(
                path="/api/v3/state",
                method="GET",
                handler=self.get_framework_state,
                category="system",
                doc="Get current framework state"
            ),
        ]

        for endpoint in endpoints:
            self.endpoints.register(endpoint)
            self.state["endpoints_registered"] += 1

    def health_check(self) -> Dict[str, Any]:
        """Framework health check endpoint."""
        return {
            "status": "healthy",
            "version": __version__,
            "modules_loaded": self.state["modules_loaded"],
            "modules_failed": self.state["modules_failed"],
            "endpoints_registered": self.state["endpoints_registered"],
            "timestamp": datetime.now().isoformat()
        }

    def get_modules(self) -> Dict[str, Any]:
        """Get list of all modules."""
        modules_info = {}
        for path, metadata in self.discovery.discovered.items():
            modules_info[path] = {
                "name": metadata.name,
                "category": metadata.category,
                "version": metadata.version,
                "status": metadata.status,
                "error": metadata.error
            }
        return modules_info

    def get_module_info(self, module: str) -> Optional[Dict[str, Any]]:
        """Get specific module information."""
        if module in self.discovery.discovered:
            metadata = self.discovery.discovered[module]
            return {
                "name": metadata.name,
                "category": metadata.category,
                "version": metadata.version,
                "path": metadata.path,
                "status": metadata.status,
                "error": metadata.error,
                "exports": metadata.exports,
                "dependencies": metadata.dependencies,
                "timestamp": metadata.timestamp
            }
        return None

    def list_endpoints(self) -> Dict[str, Any]:
        """List all registered endpoints."""
        return self.endpoints.list_endpoints()

    def list_endpoints_by_category(self, category: str) -> Dict[str, Any]:
        """List endpoints by category."""
        return self.endpoints.list_endpoints(category)

    def get_framework_state(self) -> Dict[str, Any]:
        """Get current framework state."""
        return {
            **self.state,
            "modules_info": self.get_modules(),
            "endpoint_categories": list(self.endpoints.get_categories().keys()),
            "total_endpoints": len(self.endpoints.endpoints)
        }

    def initialize(self) -> bool:
        """Initialize the framework."""
        try:
            self.logger.info(f"ARDF v3 Framework initializing (version {__version__})")
            self.load_all_modules()
            self.register_core_endpoints()
            self.state["initialized"] = True
            self.logger.info("Framework initialization complete")
            return True
        except Exception as e:
            self.logger.error(f"Framework initialization failed: {e}")
            self.state["initialized"] = False
            return False

    def get_module(self, module_path: str) -> Optional[Any]:
        """Get a loaded module."""
        return self.modules.get(module_path)

    def execute_endpoint(self, path: str, method: str = "GET", **kwargs) -> Any:
        """Execute an endpoint."""
        endpoint = self.endpoints.get_endpoint(path, method)
        if endpoint:
            try:
                return endpoint.handler(**kwargs)
            except Exception as e:
                self.logger.error(f"Endpoint execution failed: {e}")
                return {"error": str(e)}
        return {"error": f"Endpoint not found: {method} {path}"}

    def shutdown(self) -> None:
        """Shutdown the framework."""
        self.logger.info("Shutting down ARDF v3 Framework...")
        self.executor.shutdown(wait=True)
        self.logger.info("Framework shutdown complete")


def get_framework(base_path: str = ".") -> ARDFv3Framework:
    """Factory function to get framework instance."""
    return ARDFv3Framework(base_path)


if __name__ == "__main__":
    framework = get_framework()
    framework.initialize()
    print(json.dumps(framework.get_framework_state(), indent=2))
    framework.shutdown()
