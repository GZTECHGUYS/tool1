"""
core/task_graph.py
──────────────────
Task dependency graph with dynamic branching for ARDF.

Enhanced with dynamic branching:
  - Conditional task execution based on findings
  - Branch selection based on Cloudflare status
  - Parallel execution of independent tasks
  - Fallback branches on failure
  - Dynamic task generation from workflow state

The task graph manages dependencies and execution order
with support for branching based on runtime conditions.
"""

import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import deque
from pathlib import Path
from enum import Enum

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Compatibility task API expected by the tests and legacy callers
# ─────────────────────────────────────────────────────────────

class TaskStatus(Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Task:
    """Single mission task used in the orchestration graph."""
    id: str = ""
    name: str = ""
    module: str = ""
    function: str = ""
    priority: int = 1
    depends_on: List[str] = field(default_factory=list)
    args: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    max_retries: int = 0
    retries: int = 0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None
    succeeded: Optional[bool] = None

    def __init__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], dict):
            raw = dict(args[0])
            raw.update(kwargs)
            kwargs = raw
        if "function" not in kwargs and "action" in kwargs:
            kwargs["function"] = kwargs["action"]
        self.id = str(kwargs.get("id", ""))
        self.name = str(kwargs.get("name", self.id or "task"))
        self.module = str(kwargs.get("module", ""))
        self.function = str(kwargs.get("function", kwargs.get("action", "")))
        self.priority = int(kwargs.get("priority", 1))
        depends = kwargs.get("depends_on", [])
        if isinstance(depends, str):
            depends = [depends]
        self.depends_on = [str(d) for d in (depends or [])]
        self.args = dict(kwargs.get("args", {}) or {})
        self.status = kwargs.get("status", TaskStatus.PENDING)
        if not isinstance(self.status, TaskStatus):
            try:
                self.status = TaskStatus(self.status)
            except ValueError:
                self.status = TaskStatus.PENDING
        self.max_retries = int(kwargs.get("max_retries", 0))
        self.retries = int(kwargs.get("retries", 0))
        self.started_at = kwargs.get("started_at")
        self.finished_at = kwargs.get("finished_at")
        self.start_time = self.started_at
        self.end_time = self.finished_at
        self.result = kwargs.get("result")
        self.error = kwargs.get("error")
        self.succeeded = kwargs.get("succeeded")

    def __post_init__(self):
        if isinstance(self.depends_on, str):
            self.depends_on = [self.depends_on]
        if not isinstance(self.args, dict):
            self.args = {}
        if not isinstance(self.status, TaskStatus):
            self.status = TaskStatus(self.status)
        self.start_time = self.started_at
        self.end_time = self.finished_at

    @property
    def duration(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    @property
    def is_done(self) -> bool:
        return self.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED}

    @property
    def can_retry(self) -> bool:
        return self.retries < self.max_retries

    def mark_running(self) -> None:
        self.status = TaskStatus.RUNNING
        self.started_at = self.started_at or time.time()
        self.start_time = self.started_at

    def mark_completed(self, result: Any = None) -> None:
        self.status = TaskStatus.COMPLETED
        self.result = result
        self.succeeded = True
        self.finished_at = time.time()
        self.end_time = self.finished_at

    def mark_failed(self, error: str) -> None:
        self.status = TaskStatus.FAILED
        self.error = error
        self.succeeded = False
        self.finished_at = time.time()
        self.end_time = self.finished_at

    def mark_skipped(self, reason: Optional[str] = None) -> None:
        self.status = TaskStatus.SKIPPED
        self.error = reason
        self.finished_at = time.time()
        self.end_time = self.finished_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "module": self.module,
            "function": self.function,
            "status": self.status.value,
            "priority": self.priority,
            "depends_on": list(self.depends_on),
            "args": self.args,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class TaskNode:
    """A node in the task dependency graph."""
    id: str
    name: str
    module: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    condition: str = "always"
    branch: str = "main"
    is_branch_node: bool = False
    branches: List[str] = field(default_factory=list)
    confirmation_tier: int = 1
    critical: bool = False
    timeout: int = 3600
    retry_count: int = 0


class TaskGraph:
    """Compatibility wrapper for both legacy plan-based graphs and dynamic graphs."""

    def __init__(self, plan: Optional[Dict[str, Any]] = None, target: Optional[str] = None):
        self.name = "task_graph"
        self.target = target or "unknown"
        self.plan = plan or {}
        self.tasks: Dict[str, Task] = {}
        self.ready_tasks: List[Task] = []
        self._graph_ready = False
        self.nodes: List[TaskNode] = []
        self.branches: Dict[str, List[TaskNode]] = {}
        self.branch_conditions: Dict[str, str] = {}
        self.default_branch: str = "main"
        self.execution_order: List[str] = []

        if isinstance(plan, dict):
            self._load_from_plan(plan)

    def _load_from_plan(self, plan: Dict[str, Any]) -> None:
        self.name = plan.get("mission_id", self.name)
        self.target = plan.get("target", self.target)
        tasks_data = plan.get("tasks", [])
        self.tasks = {}
        for task_data in tasks_data:
            task_id = str(task_data.get("id", "task"))
            task = Task(
                id=task_id,
                name=task_data.get("name", task_id),
                module=task_data.get("module", ""),
                function=task_data.get("function", ""),
                priority=int(task_data.get("priority", 1)),
                depends_on=list(task_data.get("depends_on", []) or []),
                args=dict(task_data.get("args", {}) or {}),
                max_retries=int(task_data.get("max_retries", 0)),
            )
            self.tasks[task_id] = task

        for task in self.tasks.values():
            task.depends_on = [d for d in task.depends_on if d in self.tasks]

        self._update_ready_status()
        self._detect_cycle()

    def _detect_cycle(self) -> None:
        visiting: Set[str] = set()
        visited: Set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise ValueError("circular dependency detected")
            if task_id in visited:
                return
            visiting.add(task_id)
            for dep in self.tasks[task_id].depends_on:
                visit(dep)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in list(self.tasks):
            visit(task_id)

    def _update_ready_status(self) -> None:
        for task in self.tasks.values():
            if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED}:
                continue
            if not task.depends_on:
                task.status = TaskStatus.READY
            elif all(self.tasks.get(dep, Task(id=dep, name=dep, module="", function="")).status == TaskStatus.COMPLETED for dep in task.depends_on):
                task.status = TaskStatus.READY
        self.ready_tasks = [task for task in self.tasks.values() if task.status == TaskStatus.READY]
        self.execution_order = [task.id for task in self.topological_order()]

    def topological_order(self) -> List[Task]:
        indegree = {task_id: 0 for task_id in self.tasks}
        children = {task_id: [] for task_id in self.tasks}
        for task in self.tasks.values():
            for dep in task.depends_on:
                indegree[task.id] += 1
                children[dep].append(task.id)

        queue = deque(sorted(
            (task_id for task_id, degree in indegree.items() if degree == 0),
            key=lambda tid: (self.tasks[tid].priority, tid),
        ))
        order: List[Task] = []
        while queue:
            current = queue.popleft()
            order.append(self.tasks[current])
            for child in sorted(children[current], key=lambda tid: (self.tasks[tid].priority, tid)):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)

        if len(order) != len(self.tasks):
            raise ValueError("circular dependency detected")
        return order

    @property
    def all_done(self) -> bool:
        return all(task.is_done for task in self.tasks.values())

    def summary(self) -> Dict[str, int]:
        completed = sum(1 for task in self.tasks.values() if task.status == TaskStatus.COMPLETED)
        failed = sum(1 for task in self.tasks.values() if task.status == TaskStatus.FAILED)
        skipped = sum(1 for task in self.tasks.values() if task.status == TaskStatus.SKIPPED)
        pending = sum(1 for task in self.tasks.values() if task.status == TaskStatus.PENDING)
        ready = len(self.ready_tasks)
        return {
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "pending": pending,
            "ready": ready,
        }

    def __len__(self) -> int:
        return len(self.tasks)

    def __iter__(self):
        return iter(self.tasks.values())

    def __contains__(self, item):
        return item in self.tasks


# ─────────────────────────────────────────────────────────────
# Task Graph Builder
# ─────────────────────────────────────────────────────────────

class TaskGraphBuilder:
    """
    Build task dependency graphs with dynamic branching.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("task_graph")
        self.nodes: List[TaskNode] = []
        self.branches: Dict[str, List[TaskNode]] = {}
        self.branch_conditions: Dict[str, str] = {}

    def add_task(
        self,
        id: str,
        name: str,
        module: str,
        action: str,
        depends_on: Optional[List[str]] = None,
        condition: str = "always",
        branch: str = "main",
        confirmation_tier: int = 1,
        critical: bool = False,
        params: Optional[Dict] = None
    ) -> None:
        """Add a task node to the graph."""
        node = TaskNode(
            id=id,
            name=name,
            module=module,
            action=action,
            params=params or {},
            depends_on=depends_on or [],
            condition=condition,
            branch=branch,
            confirmation_tier=confirmation_tier,
            critical=critical
        )
        self.nodes.append(node)

        # Add to branch
        if branch not in self.branches:
            self.branches[branch] = []
        self.branches[branch].append(node)

    def add_branch(self, name: str, condition: str, tasks: List[Dict]) -> None:
        """Add a conditional branch."""
        self.branch_conditions[name] = condition
        for task_data in tasks:
            self.add_task(
                branch=name,
                condition=condition,
                **task_data
            )

    def add_cloudflare_branches(self, target: str) -> None:
        """
        Add Cloudflare-specific branches.
        """
        # Main branch (no Cloudflare)
        self.add_branch("main", "always", [
            {"id": "recon_main", "name": "Standard Reconnaissance", "module": "recon", "action": "run_recon", "params": {"depth": "normal"}},
            {"id": "exploit_main", "name": "Standard Exploitation", "module": "exploit", "action": "run_exploit", "params": {"mode": "full"}}
        ])

        # Cloudflare branch
        self.add_branch("cloudflare", "cloudflare_detected", [
            {"id": "recon_cf", "name": "Cloudflare Reconnaissance", "module": "recon", "action": "run_recon", "params": {"depth": "normal"}},
            {"id": "bypass_cf", "name": "Cloudflare Bypass", "module": "bypass", "action": "run_bypass", "params": {"technique": "all"}},
            {"id": "origin_attack", "name": "Direct Origin Attack", "module": "workflow", "action": "direct_origin", "params": {"ip": "{{bypass_cf.best_candidate}}"}},
            {"id": "exploit_origin", "name": "Origin Exploitation", "module": "exploit", "action": "run_exploit", "params": {"mode": "full"}}
        ])

        # Fallback branch (bypass failed)
        self.add_branch("fallback", "bypass_failed", [
            {"id": "recon_fallback", "name": "Fallback Reconnaissance", "module": "recon", "action": "run_recon", "params": {"depth": "depth"}},
            {"id": "social_engineering", "name": "Social Engineering", "module": "redteam", "action": "social_engineering", "params": {"vector": "phishing"}},
            {"id": "supply_chain", "name": "Supply Chain Attack", "module": "redteam", "action": "supply_chain", "params": {}}
        ])

    def build(self) -> TaskGraph:
        """Build the complete task graph."""
        # Validate dependencies
        node_ids = {n.id for n in self.nodes}
        for node in self.nodes:
            for dep in node.depends_on:
                if dep not in node_ids:
                    self.logger.warning(f"Node {node.id} depends on missing node: {dep}")

        return TaskGraph(
            name="dynamic_task_graph",
            target="current",
            nodes=self.nodes,
            branches=self.branches,
            branch_conditions=self.branch_conditions,
            default_branch="main"
        )


# ─────────────────────────────────────────────────────────────
# Task Graph Executor
# ─────────────────────────────────────────────────────────────

class TaskGraphExecutor:
    """
    Execute task graph with dynamic branching.
    """

    def __init__(
        self,
        graph: TaskGraph,
        session: Session,
        logger: Optional[ARDFLogger] = None
    ):
        self.graph = graph
        self.session = session
        self.logger = logger or get_logger("task_graph")
        self.completed: Set[str] = set()
        self.failed: Set[str] = set()
        self.skipped: Set[str] = set()
        self.results: Dict[str, Any] = {}
        self.branch_selected: Optional[str] = None

    def evaluate_condition(self, condition: str) -> bool:
        """Evaluate a branch condition."""
        if condition == "always":
            return True

        # Cloudflare conditions
        if condition == "cloudflare_detected":
            # Check recon data
            recon_path = self.session.dir("recon") / "recon_passive_summary.json"
            if recon_path.exists():
                try:
                    data = json.loads(recon_path.read_text())
                    return data.get("cloudflare", {}).get("detected", False)
                except Exception:
                    pass
            return False

        if condition == "bypass_succeeded":
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    return data.get("bypass_achieved", False)
                except Exception:
                    pass
            return False

        if condition == "bypass_failed":
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    return not data.get("bypass_achieved", False)
                except Exception:
                    pass
            return False

        # Check if a specific task succeeded
        if condition.startswith("task_succeeded."):
            task_id = condition[15:]
            return task_id in self.completed

        # Check if a specific task failed
        if condition.startswith("task_failed."):
            task_id = condition[12:]
            return task_id in self.failed

        return True

    def select_branch(self, node: TaskNode) -> str:
        """
        Determine which branch to follow from a branch node.
        """
        if not node.is_branch_node or not node.branches:
            return node.branch

        for branch in node.branches:
            condition = self.graph.branch_conditions.get(branch, "never")
            if self.evaluate_condition(condition):
                self.branch_selected = branch
                return branch

        return self.graph.default_branch

    def get_ready_tasks(self) -> List[TaskNode]:
        """Get tasks ready for execution."""
        ready = []
        for node in self.graph.nodes:
            if node.id in self.completed or node.id in self.failed or node.id in self.skipped:
                continue

            # Check if all dependencies are satisfied
            deps_met = all(dep in self.completed for dep in node.depends_on)
            if not deps_met:
                continue

            # Check if task belongs to selected branch
            if node.is_branch_node:
                # Branch node itself is always ready if deps met
                ready.append(node)
            elif node.branch != self.branch_selected and self.branch_selected is not None:
                # Skip tasks not in selected branch
                self.skipped.add(node.id)
                continue

            ready.append(node)

        return ready

    def execute_task(self, node: TaskNode) -> Dict:
        """Execute a single task."""
        self.logger.info(f"Executing: {node.name} ({node.module}.{node.action})")

        # For branch nodes, just select branch
        if node.is_branch_node:
            selected = self.select_branch(node)
            self.logger.info(f"Branch selected: {selected}")
            return {"status": "branch", "selected": selected}

        try:
            module = __import__(f"modules.{node.module}", fromlist=[""])
            func = getattr(module, node.action)

            params = node.params.copy()
            params["session"] = self.session
            params["logger"] = self.logger

            # Add branch context
            params["branch"] = self.branch_selected
            params["completed_tasks"] = list(self.completed)

            result = func(**params)
            return {"status": "success", "result": result}
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Module/action not found: {node.module}.{node.action}")
            return {"status": "failed", "error": str(e)}
        except Exception as e:
            self.logger.error(f"Task failed: {e}")
            return {"status": "failed", "error": str(e)}

    def execute(self) -> Dict[str, Any]:
        """
        Execute the task graph.
        """
        self.logger.banner("TASK GRAPH EXECUTION", style="bold cyan")

        # Find branch nodes
        branch_nodes = [n for n in self.graph.nodes if n.is_branch_node]

        # Handle branch selection first
        for node in branch_nodes:
            if node.id in self.completed:
                continue
            result = self.execute_task(node)
            if result.get("status") == "branch":
                self.branch_selected = result.get("selected")
                self.completed.add(node.id)
                self.results[node.id] = result

        # Execute remaining tasks
        while True:
            ready = self.get_ready_tasks()
            if not ready:
                break

            for node in ready:
                result = self.execute_task(node)

                if result["status"] == "success":
                    self.completed.add(node.id)
                    self.results[node.id] = result
                elif result["status"] == "failed":
                    self.failed.add(node.id)
                    self.results[node.id] = result
                    if node.critical:
                        self.logger.error(f"Critical task failed: {node.id}")
                        return {"status": "failed", "task": node.id, "error": result.get("error")}
                else:
                    self.skipped.add(node.id)

        # Determine final status
        failed_count = len(self.failed)
        completed_count = len(self.completed)
        total = len(self.graph.nodes)

        return {
            "status": "completed" if failed_count == 0 else "partial_success",
            "total_tasks": total,
            "completed": completed_count,
            "failed": failed_count,
            "skipped": len(self.skipped),
            "branch_selected": self.branch_selected,
            "results": self.results
        }


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def build_and_execute_graph(
    session: Session,
    target: str,
    logger: Optional[ARDFLogger] = None,
    include_cloudflare_branches: bool = True,
) -> Dict[str, Any]:
    """
    Build and execute a task graph with dynamic branching.

    Args:
        session: Active ARDF session
        target: Target domain/IP
        logger: ARDFLogger instance
        include_cloudflare_branches: Add Cloudflare-specific branches

    Returns:
        Execution results
    """
    if logger is None:
        logger = get_logger("task_graph")

    builder = TaskGraphBuilder(logger)

    # Add Cloudflare branches if requested
    if include_cloudflare_branches:
        builder.add_cloudflare_branches(target)

    # Add additional tasks
    builder.add_task(
        id="report_final",
        name="Generate Final Report",
        module="report",
        action="generate_report",
        depends_on=["recon_main", "exploit_main", "bypass_cf", "origin_attack", "exploit_origin"],
        condition="always",
        confirmation_tier=1
    )

    graph = builder.build()
    executor = TaskGraphExecutor(graph, session, logger)

    return executor.execute()