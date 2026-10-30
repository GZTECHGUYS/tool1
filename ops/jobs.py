"""Background playbook jobs with human-approval gates and streamed logs."""
from __future__ import annotations

import importlib
import inspect
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ops.scope import ScopeGuard, ScopeViolation, CONFIG_PATH as SCOPE_CONFIG

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

TIER3_TAGS = {"exploit", "passwords", "post", "privesc", "persistence",
              "rce", "brute-force", "c2", "exfiltration"}


def _publish(event_type: str, data: dict, session_id: str = "") -> None:
    try:
        from ops.events import publish
        publish(event_type, data, session_id)
    except Exception:
        pass


def _dash_config() -> dict:
    if HAVE_YAML and SCOPE_CONFIG.exists():
        try:
            return ((yaml.safe_load(SCOPE_CONFIG.read_text()) or {})
                    .get("dashboard", {}) or {})
        except Exception:
            return {}
    return {}


class JobManager:
    """Run playbooks in background threads; Tier-2/3 tasks pause for approval."""

    def __init__(self, scope: Optional[ScopeGuard] = None):
        self.scope = scope or ScopeGuard()
        cfg = _dash_config()
        self.approval_timeout = int(cfg.get("approval_timeout_seconds", 600))
        self.require_tier2 = bool(cfg.get("require_approval_tier2", True))
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.approvals: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ── jobs ───────────────────────────────────────────────

    def create_job(self, playbook: str, target: str, user: str = "?",
                   auto_approve: bool = False) -> Dict[str, Any]:
        self.scope.require(target)
        try:  # non-blocking pre-engagement OPSEC note
            from modules.opsec_audit import audit as _oaudit
            from modules.logger import get_logger as _gl
            _ov = _oaudit(None, _gl("ops.jobs"))
            if _ov["verdict"] != "GO":
                _gl("ops.jobs").warning(
                    "OPSEC " + _ov["verdict"] + ": " + "; ".join(
                        i["check"] + "=" + i["status"]
                        for i in _ov["items"] if i["status"] != "PASS"))
        except Exception:
            pass
        from modules.session import new_session, Mode
        from playbook.loader import PlaybookLoader
        from playbook.executor import PlaybookExecutor
        from modules.logger import get_logger

        loader = PlaybookLoader()
        pb = loader.load(playbook)  # raises FileNotFoundError
        mode = Mode(pb.get("mode", "red")) if pb.get("mode") in list(Mode) else Mode.FULL
        session = new_session(target=target, mode=mode,
                              name=f"{pb.get('name', playbook)}:{target}")
        executor = PlaybookExecutor(session)
        plan = executor.build_plan(pb)
        if plan is None:
            raise ValueError("Playbook failed validation — see logs")

        phases = {p.get("id"): p for p in pb.get("phases", [])}
        job_id = f"job_{uuid.uuid4().hex[:8]}"
        job: Dict[str, Any] = {
            "id": job_id, "playbook": pb.get("name", playbook),
            "target": target, "user": user,
            "session_id": session.meta.session_id,
            "status": "queued", "created": datetime.now().isoformat(),
            "tasks": [], "log": deque(maxlen=2000),
            "auto_approve": auto_approve,
        }
        with self._lock:
            self.jobs[job_id] = job
        job["cancel"] = threading.Event()
        _publish("job.queued", {"job_id": job_id, "playbook": job["playbook"],
                                "target": target},
                 session.meta.session_id)
        t = threading.Thread(target=self._run, args=(job_id, plan, phases),
                             daemon=True)
        t.start()
        return self.describe(job_id)

    def cancel(self, job_id: str) -> Dict[str, Any]:
        """Kill-switch: job stops after the current task."""
        job = self.jobs.get(job_id)
        if not job:
            return {"error": "job not found"}
        job["cancel"].set()
        if job.get("status") in ("queued", "waiting_approval"):
            job["status"] = "killed"
        return {"id": job_id, "status": job.get("status", "killed")}

    def describe(self, job_id: str) -> Dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job:
            return {"error": "job not found"}
        return {k: (list(v) if k == "log" else v) for k, v in job.items()
                if k not in ("log", "cancel", "logger")} | {
            "log_tail": list(job["log"])[-50:]}

    def list_jobs(self) -> List[Dict[str, Any]]:
        return [self.describe(jid) for jid in self.jobs]

    def job_log(self, job_id: str, since: int = 0) -> Dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job:
            return {"error": "job not found"}
        entries = list(job["log"])
        return {"entries": entries[since:], "next": len(entries)}

    # ── approvals ──────────────────────────────────────────

    def list_approvals(self, pending_only: bool = True) -> List[Dict[str, Any]]:
        out = []
        for a in self.approvals.values():
            if pending_only and a["status"] != "pending":
                continue
            out.append({k: v for k, v in a.items() if k != "event"})
        return out

    def decide(self, approval_id: str, approved: bool, user: str = "?",
               confirm_text: str = "") -> Dict[str, Any]:
        a = self.approvals.get(approval_id)
        if not a:
            return {"error": "approval not found"}
        if a["status"] != "pending":
            return {"error": f"already {a['status']}"}
        if a["tier"] == 3 and approved and confirm_text.strip() != "CONFIRM":
            return {"error": "Tier-3 requires confirm_text='CONFIRM'"}
        a["status"] = "approved" if approved else "denied"
        a["decided_by"] = user
        a["decided_at"] = datetime.now().isoformat()
        a["event"].set()
        _publish("approval.decided",
                 {"approval_id": approval_id,
                  "decision": a["status"], "task": a.get("task", ""),
                  "job_id": a.get("job_id", ""),
                  "by": user})
        return {"status": a["status"]}

    # ── runner ─────────────────────────────────────────────

    def _emit(self, job: Dict, msg: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        job["log"].append(line)
        try:
            job["logger"].info(msg)
        except Exception:
            pass

    def _run(self, job_id: str, plan: Dict, phases: Dict[str, Dict]) -> None:
        from modules.logger import get_logger
        job = self.jobs[job_id]
        job["logger"] = get_logger(f"job.{job_id}")
        job["status"] = "running"
        _publish("job.started", {"job_id": job_id}, job.get("session_id", ""))
        try:
            for task in plan.get("tasks", []):
                if job["cancel"].is_set():
                    job["status"] = "killed"
                    self._emit(job, "KILLED by operator")
                    _publish("job.killed", {"job_id": job_id})
                    return
                merged = dict(task)
                extra = phases.get(task.get("id"), {})
                merged.update({k: v for k, v in extra.items()
                               if k not in merged})
                self._run_task(job, merged)
            job["status"] = "complete"
            self._emit(job, "DONE — all tasks finished")
            _publish("job.complete", {"job_id": job_id})
        except Exception as e:
            job["status"] = "failed"
            self._emit(job, f"JOB FAILED: {e}")
            _publish("job.failed", {"job_id": job_id, "error": str(e)})

    def _tier(self, task: Dict) -> int:
        tags = {str(t).lower() for t in task.get("tags", [])}
        if tags & TIER3_TAGS:
            return 3
        return 2

    def _run_task(self, job: Dict, task: Dict) -> None:
        name = task.get("name", task.get("id", "?"))
        needs_gate = bool(task.get("confirmation")) and (
            self.require_tier2 or self._tier(task) == 3)
        if needs_gate and not job["auto_approve"]:
            tier = self._tier(task)
            ap_id = f"ap_{uuid.uuid4().hex[:8]}"
            event = threading.Event()
            with self._lock:
                self.approvals[ap_id] = {
                    "id": ap_id, "job_id": job["id"],
                    "task": name, "tier": tier,
                    "message": task.get("confirmation_message", ""),
                    "status": "pending", "event": event,
                    "created": datetime.now().isoformat(),
                }
            self._emit(job, f"GATE tier-{tier} waiting approval: {name} ({ap_id})")
            _publish("approval.pending", {"job_id": job["id"], "approval_id": ap_id,
                                      "task": name, "tier": tier},
                 job.get("session_id", ""))
            job["status"] = "waiting_approval"
            waited, ok = 0.0, False
            while waited < self.approval_timeout:
                if job["cancel"].is_set():
                    self.approvals[ap_id]["status"] = "killed"
                    self._emit(job, f"KILLED {name} while waiting approval")
                    job["status"] = "killed"
                    return
                if event.wait(timeout=1.0):
                    ok = True
                    break
                waited += 1.0
            decision = self.approvals[ap_id]["status"]
            if not ok:
                self.approvals[ap_id]["status"] = "timeout"
                self._emit(job, f"SKIP {name} — approval timeout")
                _publish("approval.decided", {"approval_id": ap_id,
                                          "decision": "timeout"})
                job["status"] = "running"
                return
            if decision != "approved":
                self._emit(job, f"SKIP {name} — {decision} by operator")
                job["status"] = "running"
                return
            self._emit(job, f"APPROVED {name} — executing")
            _publish("approval.decided", {"approval_id": ap_id, "decision": decision})
            job["status"] = "running"

        self._emit(job, f"START {name} [{task.get('module')}.{task.get('function')}]")
        trec = {"name": name, "status": "running",
                "started": datetime.now().isoformat()}
        job["tasks"].append(trec)
        try:
            result = self._invoke(job, task)
            trec["status"] = "done"
            trec["result"] = str(result)[:500]
            self._emit(job, f"OK {name}")
        except Exception as e:
            trec["status"] = "failed"
            trec["error"] = str(e)[:500]
            self._emit(job, f"FAIL {name}: {e}")
            self._suggest_recovery(job, name, trec)

    def _suggest_recovery(self, job: Dict, name: str, trec: Dict) -> None:
        """C17/C18: on task failure, ask the tactician for an alternate
        tactic grounded in live session findings, and consult the v2
        failure-recovery detector when available."""
        try:
            from modules.session import resume_session
            from ai.tactician import Tactician
            session = resume_session(job["session_id"])
            fb = Tactician(session).suggest_fallback_on_failure(
                job["target"], [name], session.get_findings())
            trec["recovery"] = {
                "recommendation": fb.get("recommendation", ""),
                "fallback": fb.get("fallback", [])[:3],
                "alternative_vectors": fb.get("alternative_vectors", [])[:5],
            }
            rec = fb.get("recommendation") or "; ".join(
                fb.get("fallback", [])[:2])
            self._emit(job, f"RECOVERY suggestion for {name}: {rec[:300]}")
        except Exception as e:
            self._emit(job, f"recovery advisor unavailable: {e}")
        try:
            from ardf_v2_failure_recovery import FailureDetector
            det = FailureDetector()
            kind = det.classify(job["target"], name) if hasattr(det, "classify") else None
            if kind:
                trec.setdefault("recovery", {})["failure_class"] = str(kind)
        except Exception:
            pass

    def _invoke(self, job: Dict, task: Dict) -> Any:
        from modules.session import resume_session
        mod_name = task.get("module", "modules.recon")
        fn_name = task.get("function", "run_recon")
        mod = importlib.import_module(mod_name)
        fn = getattr(mod, fn_name)
        session = resume_session(job["session_id"])
        logger = job.get("logger")

        # Known entry-point conventions (mirror ardf.py)
        if (mod_name, fn_name) == ("modules.recon", "run_recon"):
            depth = (task.get("args", {}) or {}).get("depth",
                    task.get("depth", "normal"))
            return fn(job["target"], depth, session, logger)
        if (mod_name, fn_name) == ("modules.intel", "run_intel"):
            return fn(session, logger)
        if (mod_name, fn_name) == ("modules.exploit", "run_exploit"):
            kwargs = {"mode": "full"}
            if "exploit_mode" in task:
                kwargs["exploit_mode"] = task["exploit_mode"]
            try:
                sig = inspect.signature(fn)
                kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
            except (TypeError, ValueError):
                pass
            return fn(session, logger, **kwargs)
        if (mod_name, fn_name) == ("modules.report", "generate_report"):
            settings = task.get("settings", {}) or {}
            try:
                sig = inspect.signature(fn)
                extra = {k: v for k, v in settings.items() if k in sig.parameters}
            except (TypeError, ValueError):
                extra = {}
            return fn(session, logger, **extra)

        # Generic fallback: match by parameter name
        hints = {"target": job["target"], "session": session, "logger": logger}
        hints.update(task.get("args", {}) or {})
        try:
            sig = inspect.signature(fn)
            params = sig.parameters
            if any(p.kind == inspect.Parameter.VAR_KEYWORD
                   for p in params.values()):
                return fn(**hints)
            return fn(**{k: v for k, v in hints.items() if k in params})
        except TypeError:
            return fn(session, logger)
