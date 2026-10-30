#!/usr/bin/env python3
"""ARDF v3 Endpoint Registry - Dynamic mapping for all framework endpoints."""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from datetime import datetime


class HTTPMethod(Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


@dataclass
class Parameter:
    """Endpoint parameter definition."""
    name: str
    type: str
    required: bool = False
    default: Any = None
    description: str = ""


@dataclass
class Endpoint:
    """Complete endpoint definition with full metadata."""
    path: str
    method: HTTPMethod
    handler: Callable
    category: str
    name: str
    description: str = ""
    parameters: List[Parameter] = field(default_factory=list)
    returns: str = "application/json"
    requires_auth: bool = False
    rate_limit: Optional[int] = None
    timeout: int = 30
    tags: List[str] = field(default_factory=list)


class EndpointCategory(Enum):
    """Endpoint categories."""
    SYSTEM = "system"
    RECON = "recon"
    EXPLOITATION = "exploitation"
    EVASION = "evasion"
    LATERAL = "lateral_movement"
    PERSISTENCE = "persistence"
    PRIVILEGE = "privilege_escalation"
    PAYLOAD = "payload_delivery"
    C2 = "c2"
    DEFENSE = "defense"
    VALIDATION = "validation"
    REPORTING = "reporting"
    OSINT = "osint"
    TOOLS = "tools"
    WORKFLOW = "workflow"
    ADMIN = "admin"


class ARDFv3EndpointRegistry:
    """Central endpoint registry for ARDF v3."""

    def __init__(self):
        self.endpoints: Dict[str, Endpoint] = {}
        self.categories: Dict[str, List[str]] = {}
        self.auth_tokens: Dict[str, Dict] = {}
        self.stats = {
            "total_registered": 0,
            "total_called": 0,
            "by_category": {},
            "last_updated": datetime.now().isoformat()
        }

    def register_endpoint(self, endpoint: Endpoint) -> None:
        """Register a new endpoint."""
        key = f"{endpoint.method.value}:{endpoint.path}"
        self.endpoints[key] = endpoint

        if endpoint.category not in self.categories:
            self.categories[endpoint.category] = []
        self.categories[endpoint.category].append(key)

        self.stats["total_registered"] += 1
        self.stats["by_category"][endpoint.category] = \
            self.stats["by_category"].get(endpoint.category, 0) + 1

    def get_endpoint(self, path: str, method: HTTPMethod = HTTPMethod.GET) -> Optional[Endpoint]:
        """Get endpoint by path and method."""
        key = f"{method.value}:{path}"
        return self.endpoints.get(key)

    def list_endpoints(self, category: Optional[str] = None) -> Dict[str, Any]:
        """List all endpoints, optionally filtered by category."""
        result = {}
        for key, endpoint in self.endpoints.items():
            if category and endpoint.category != category:
                continue

            param_list = [
                {
                    "name": p.name,
                    "type": p.type,
                    "required": p.required,
                    "default": p.default,
                    "description": p.description
                }
                for p in endpoint.parameters
            ]

            result[key] = {
                "path": endpoint.path,
                "method": endpoint.method.value,
                "category": endpoint.category,
                "name": endpoint.name,
                "description": endpoint.description,
                "parameters": param_list,
                "returns": endpoint.returns,
                "requires_auth": endpoint.requires_auth,
                "rate_limit": endpoint.rate_limit,
                "timeout": endpoint.timeout,
                "tags": endpoint.tags
            }

        return result

    def get_by_category(self, category: str) -> List[Endpoint]:
        """Get all endpoints in a category."""
        if category not in self.categories:
            return []
        return [self.endpoints[key] for key in self.categories[category]]

    def get_by_tag(self, tag: str) -> List[Endpoint]:
        """Get all endpoints with a specific tag."""
        return [e for e in self.endpoints.values() if tag in e.tags]

    def get_categories(self) -> Dict[str, List[str]]:
        """Get all categories and their endpoint count."""
        return {
            cat: len(endpoints) for cat, endpoints in self.categories.items()
        }

    def validate_endpoint(self, path: str, method: HTTPMethod, **kwargs) -> Dict[str, Any]:
        """Validate endpoint call parameters."""
        endpoint = self.get_endpoint(path, method)
        if not endpoint:
            return {"valid": False, "error": "Endpoint not found"}

        errors = []
        for param in endpoint.parameters:
            if param.required and param.name not in kwargs:
                errors.append(f"Missing required parameter: {param.name}")
            elif param.name in kwargs:
                value = kwargs[param.name]
                if not self._validate_type(value, param.type):
                    errors.append(f"Invalid type for {param.name}: expected {param.type}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "endpoint": endpoint.name
        }

    def _validate_type(self, value: Any, type_str: str) -> bool:
        """Validate value against type string."""
        type_map = {
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "any": lambda x: True
        }
        validator = type_map.get(type_str, lambda x: True)
        return isinstance(value, validator)

    def record_call(self, path: str, method: HTTPMethod) -> None:
        """Record an endpoint call."""
        self.stats["total_called"] += 1
        self.stats["last_updated"] = datetime.now().isoformat()

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        return {
            **self.stats,
            "categories": self.get_categories(),
            "total_endpoints": len(self.endpoints)
        }

    def export_openapi(self) -> Dict[str, Any]:
        """Export endpoints as OpenAPI 3.0 spec."""
        paths = {}
        for key, endpoint in self.endpoints.items():
            if endpoint.path not in paths:
                paths[endpoint.path] = {}

            param_list = [
                {
                    "name": p.name,
                    "in": "query" if endpoint.method != HTTPMethod.POST else "body",
                    "required": p.required,
                    "schema": {"type": p.type},
                    "description": p.description
                }
                for p in endpoint.parameters
            ]

            paths[endpoint.path][endpoint.method.value.lower()] = {
                "summary": endpoint.name,
                "description": endpoint.description,
                "parameters": param_list,
                "tags": [endpoint.category],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            endpoint.returns: {}
                        }
                    }
                }
            }

        return {
            "openapi": "3.0.0",
            "info": {
                "title": "ARDF v3 API",
                "version": "3.0.0",
                "description": "Autonomous Red Team Deployment Framework v3 REST API"
            },
            "paths": paths
        }

    def export_postman(self) -> Dict[str, Any]:
        """Export endpoints as Postman collection."""
        items = []
        for key, endpoint in self.endpoints.items():
            item = {
                "name": endpoint.name,
                "request": {
                    "method": endpoint.method.value,
                    "url": {
                        "raw": f"{{{{BASE_URL}}}}{endpoint.path}",
                        "host": ["{{BASE_URL}}"],
                        "path": endpoint.path.split("/")[1:]
                    },
                    "description": endpoint.description,
                    "header": [
                        {
                            "key": "Content-Type",
                            "value": "application/json"
                        }
                    ]
                },
                "response": []
            }

            if endpoint.parameters:
                item["request"]["url"]["query"] = [
                    {
                        "key": p.name,
                        "value": str(p.default) if p.default else "",
                        "disabled": not p.required
                    }
                    for p in endpoint.parameters
                ]

            items.append(item)

        return {
            "info": {
                "name": "ARDF v3 API",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": items,
            "variable": [
                {
                    "key": "BASE_URL",
                    "value": "http://localhost:5000"
                }
            ]
        }


def create_system_endpoints(framework: Any) -> List[Endpoint]:
    """Create system-level endpoints."""
    return [
        Endpoint(
            path="/api/v3/health",
            method=HTTPMethod.GET,
            handler=framework.health_check,
            category="system",
            name="Health Check",
            description="Framework health status",
            returns="application/json"
        ),
        Endpoint(
            path="/api/v3/modules",
            method=HTTPMethod.GET,
            handler=framework.get_modules,
            category="system",
            name="List Modules",
            description="List all loaded modules",
            parameters=[
                Parameter("category", "str", False, None, "Filter by category")
            ]
        ),
        Endpoint(
            path="/api/v3/endpoints",
            method=HTTPMethod.GET,
            handler=framework.list_endpoints,
            category="system",
            name="List Endpoints",
            description="List all registered API endpoints",
            parameters=[
                Parameter("category", "str", False, None, "Filter by category")
            ]
        ),
        Endpoint(
            path="/api/v3/state",
            method=HTTPMethod.GET,
            handler=framework.get_framework_state,
            category="system",
            name="Framework State",
            description="Get current framework state and statistics"
        ),
    ]


if __name__ == "__main__":
    registry = ARDFv3EndpointRegistry()
    print(json.dumps(registry.get_stats(), indent=2))
