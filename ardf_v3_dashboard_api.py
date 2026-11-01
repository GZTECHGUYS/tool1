#!/usr/bin/env python3
"""ARDF v3 Dashboard API - Flask REST API for framework monitoring and control."""

import os
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from functools import wraps
from datetime import datetime, timedelta
import hashlib

try:
    from flask import Flask, jsonify, request, render_template_string, send_file, Response
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class ARDFv3DashboardAPI:
    """Dashboard API server for ARDF v3."""

    def __init__(self, framework, host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
        if not FLASK_AVAILABLE:
            raise RuntimeError("Flask is required for dashboard. Install with: pip install flask flask-cors")

        self.framework = framework
        self.host = host
        self.port = port
        self.debug = debug
        self.app = Flask(__name__)
        self.logger = logging.getLogger("ARDFv3Dashboard")

        CORS(self.app)

        self.auth_key = os.getenv("ARDF_AUTH_KEY", "default_key_change_me")
        self.active_sessions = {}
        self.request_log = []
        self.max_log_size = 1000

        # Ops layer (sessions, jobs, approvals, C2, scope)
        from ops.auth import AuthManager
        from ops.jobs import JobManager
        from ops.scope import ScopeGuard
        self.ops_auth = AuthManager()
        self.jobs = JobManager()
        self.scope = self.jobs.scope

        self._register_routes()

    def _register_routes(self) -> None:
        """Register all dashboard routes."""
        @self.app.route("/", methods=["GET"])
        def index():
            return self._serve_static("index.html", "text/html")

        @self.app.route("/favicon.ico", methods=["GET"])
        def favicon():
            return Response(status=204)

        @self.app.route("/app.js", methods=["GET"])
        def app_js():
            # Served unauthenticated (login page needs it); no-store for now.
            return self._serve_static("app.js", "application/javascript")

        @self.app.route("/style.css", methods=["GET"])
        def style_css():
            return self._serve_static("style.css", "text/css")

        @self.app.route("/api/v3/auth/login", methods=["POST"])
        def login():
            return self.handle_login()

        @self.app.route("/api/v3/auth/validate", methods=["GET"])
        @self.require_auth
        def validate_token():
            return jsonify({"valid": True, "timestamp": datetime.now().isoformat()})

        @self.app.route("/api/v3/dashboard/summary", methods=["GET"])
        @self.require_auth
        def dashboard_summary():
            return jsonify(self.get_dashboard_summary())

        @self.app.route("/api/v3/modules/list", methods=["GET"])
        @self.require_auth
        def list_modules():
            return jsonify(self.framework.get_modules())

        @self.app.route("/api/v3/modules/<module_id>", methods=["GET"])
        @self.require_auth
        def get_module(module_id):
            info = self.framework.get_module_info(module_id)
            return jsonify(info) if info else (jsonify({"error": "Module not found"}), 404)

        @self.app.route("/api/v3/endpoints/list", methods=["GET"])
        @self.require_auth
        def list_endpoints():
            category = request.args.get("category")
            return jsonify(self.framework.list_endpoints_by_category(category) if category else self.framework.list_endpoints())

        @self.app.route("/api/v3/endpoints/categories", methods=["GET"])
        @self.require_auth
        def get_endpoint_categories():
            return jsonify({
                "categories": list(self.framework.endpoints.get_categories().keys()),
                "count": len(self.framework.endpoints.endpoints)
            })

        @self.app.route("/api/v3/framework/state", methods=["GET"])
        @self.require_auth
        def framework_state():
            return jsonify(self.framework.get_framework_state())

        @self.app.route("/api/v3/framework/health", methods=["GET"])
        @self.require_auth
        def health():
            return jsonify(self.framework.health_check())

        @self.app.route("/api/v3/framework/stats", methods=["GET"])
        @self.require_auth
        def stats():
            return jsonify(self.get_framework_stats())

        @self.app.route("/api/v3/execution/run", methods=["POST"])
        @self.require_auth
        def execute_endpoint():
            return self.execute_user_endpoint()

        @self.app.route("/api/v3/logs", methods=["GET"])
        @self.require_auth
        def get_logs():
            limit = request.args.get("limit", 100, type=int)
            offset = request.args.get("offset", 0, type=int)
            return jsonify({
                "logs": self.request_log[offset:offset+limit],
                "total": len(self.request_log),
                "limit": limit,
                "offset": offset
            })

        @self.app.route("/api/v3/export/openapi", methods=["GET"])
        @self.require_auth
        def export_openapi():
            spec = self.framework.endpoints.export_openapi()
            return jsonify(spec)

        @self.app.route("/api/v3/export/postman", methods=["GET"])
        @self.require_auth
        def export_postman():
            collection = self.framework.endpoints.export_postman()
            return jsonify(collection)

        # ── Ops console (sessions / jobs / approvals) ──

        def _session_or_404(sid):
            from modules.session import get_manager
            try:
                return get_manager().load(sid), None
            except Exception as e:
                return None, (jsonify({"error": f"session not found: {e}"}), 404)

        @self.app.route("/api/v3/sessions", methods=["GET"])
        @self.require_auth
        def list_sessions():
            from modules.session import get_manager
            return jsonify({"sessions": get_manager().list_sessions()})

        @self.app.route("/api/v3/sessions", methods=["POST"])
        @self.require_auth
        def create_session():
            from modules.session import new_session, Mode
            data = request.get_json() or {}
            target = data.get("target", "")
            ok, reason = self.scope.validate(target)
            if not ok:
                return jsonify({"error": reason}), 403
            mode = data.get("mode", "full")
            try:
                s = new_session(target=target, mode=Mode(mode),
                                name=data.get("name"),
                                tags=data.get("tags"))
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            self.ops_auth.audit("session.create",
                                getattr(request, "ops_user", "?"), "success", target)
            return jsonify({"session_id": s.meta.session_id,
                            "target": target}), 201

        @self.app.route("/api/v3/sessions/<sid>", methods=["GET"])
        @self.require_auth
        def get_session(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            return jsonify({"meta": {"session_id": s.meta.session_id,
                                     "target": s.meta.target,
                                     "mode": str(getattr(s.meta, "mode", "")),
                                     "status": str(getattr(s.meta, "status", ""))},
                            "findings_count": len(s.get_findings())})

        @self.app.route("/api/v3/sessions/<sid>", methods=["DELETE"])
        @self.require_auth
        def delete_session(sid):
            from modules.session import get_manager
            data = request.get_json(silent=True) or {}
            if data.get("confirm_text", "").strip() != "DELETE":
                return jsonify({"error": "pass confirm_text='DELETE'"}), 403
            try:
                get_manager().delete(sid)
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            self.ops_auth.audit("session.delete",
                                getattr(request, "ops_user", "?"),
                                "success", sid)
            return jsonify({"deleted": sid})

        @self.app.route("/api/v3/playbooks", methods=["GET"])
        @self.require_auth
        def list_playbooks():
            from playbook.loader import PlaybookLoader
            return jsonify({"playbooks": PlaybookLoader().list_available()})

        @self.app.route("/api/v3/jobs", methods=["POST"])
        @self.require_auth
        def start_job():
            data = request.get_json() or {}
            try:
                job = self.jobs.create_job(
                    playbook=data.get("playbook", "full"),
                    target=data.get("target", ""),
                    user=getattr(request, "ops_user", "?"),
                    auto_approve=bool(data.get("auto_approve", False)))
            except Exception as e:
                status = 403 if "SCOPE" in type(e).__name__.upper() or "scope" in str(e).lower() else 400
                return jsonify({"error": str(e)}), status
            self.ops_auth.audit("job.start",
                                getattr(request, "ops_user", "?"), "success",
                                f"{job['playbook']} -> {job['target']}")
            return jsonify(job), 201

        @self.app.route("/api/v3/jobs", methods=["GET"])
        @self.require_auth
        def list_jobs():
            return jsonify({"jobs": self.jobs.list_jobs()})

        @self.app.route("/api/v3/jobs/<jid>", methods=["GET"])
        @self.require_auth
        def get_job(jid):
            return jsonify(self.jobs.describe(jid))

        @self.app.route("/api/v3/jobs/<jid>", methods=["DELETE"])
        @self.require_auth
        def kill_job(jid):
            out = self.jobs.cancel(jid)
            self.ops_auth.audit("job.kill",
                                getattr(request, "ops_user", "?"),
                                "success", jid)
            return jsonify(out)

        # ── auto-exploit ──

        @self.app.route("/api/v3/sessions/<sid>/autoexploit", methods=["POST"])
        @self.require_auth
        def autoexploit_start(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from ops import autoexploit as _ax
            data = request.get_json() or {}
            mode = data.get("mode", "prove")
            if mode not in ("prove", "assist"):
                return jsonify({"error": "mode must be prove|assist"}), 400
            try:
                out = _ax.start(sid, mode, int(data.get("max_chains", 8)))
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            self.ops_auth.audit("autoexploit.start",
                                getattr(request, "ops_user", "?"),
                                "success", f"{sid}:{mode}")
            return jsonify(out), 201

        @self.app.route("/api/v3/autoexploit/<rid>", methods=["GET"])
        @self.require_auth
        def autoexploit_status(rid):
            from ops import autoexploit as _ax
            return jsonify(_ax.describe(rid))

        @self.app.route("/api/v3/autoexploit/<rid>", methods=["DELETE"])
        @self.require_auth
        def autoexploit_kill(rid):
            from ops import autoexploit as _ax
            return jsonify(_ax.kill(rid))

        @self.app.route("/api/v3/jobs/<jid>/log", methods=["GET"])
        @self.require_auth
        def job_log(jid):
            since = request.args.get("since", 0, type=int)
            return jsonify(self.jobs.job_log(jid, since))

        @self.app.route("/api/v3/events/stream", methods=["GET"])
        def events_stream():
            # Unified console SSE: jobs, findings, approvals, C2.
            token = request.args.get("token", "")
            since = request.args.get("since", 0, type=int)
            if not self.ops_auth.check(token) and token not in self.active_sessions:
                return jsonify({"error": "Unauthorized"}), 401

            from ops import events as _ev

            def gen():
                # replay missed events up front
                try:
                    for ev in _ev.since(since):
                        yield f"id: {ev['id']}\ndata: {json.dumps(ev)}\n\n"
                except Exception:
                    pass
                for _ in range(2400):  # ~20 min then client reconnects
                    import time as _t
                    for ev in _ev.since(seen[0]):
                        yield f"id: {ev['id']}\ndata: {json.dumps(ev)}\n\n"
                        seen[0] = max(seen[0], ev["id"])
                    yield ": ping\n\n"
                    _t.sleep(1)

            seen = [since]
            resp = Response(gen(), mimetype="text/event-stream")
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["X-Accel-Buffering"] = "no"
            return resp

        @self.app.route("/api/v3/jobs/<jid>/stream", methods=["GET"])
        def job_stream(jid):
            # SSE live tail (token via query for EventSource)
            token = request.args.get("token", "")
            if not self.ops_auth.check(token) and token not in self.active_sessions:
                return jsonify({"error": "Unauthorized"}), 401

            def gen():
                seen = 0
                for _ in range(600):  # ~10 min cap
                    import time as _t
                    data = self.jobs.job_log(jid, seen)
                    if "error" in data:
                        yield f"data: {json.dumps(data)}\n\n"
                        break
                    for line in data["entries"]:
                        yield f"data: {json.dumps({'line': line})}\n\n"
                    seen = data["next"]
                    job = self.jobs.jobs.get(jid, {})
                    if job.get("status") in ("complete", "failed"):
                        yield f"data: {json.dumps({'status': job.get('status')})}\n\n"
                        break
                    _t.sleep(1)
            return Response(gen(), mimetype="text/event-stream")

        @self.app.route("/api/v3/approvals", methods=["GET"])
        @self.require_auth
        def list_approvals():
            return jsonify({"approvals": self.jobs.list_approvals()})

        @self.app.route("/api/v3/approvals/<aid>", methods=["POST"])
        @self.require_auth
        def decide_approval(aid):
            data = request.get_json() or {}
            out = self.jobs.decide(aid, bool(data.get("approved", False)),
                                   getattr(request, "ops_user", "?"),
                                   data.get("confirm_text", ""))
            self.ops_auth.audit(
                "approval." + out.get("status", "error"),
                getattr(request, "ops_user", "?"), "success", aid)
            return jsonify(out), (200 if "status" in out else 400)

        # ── Findings / graph / reports ──

        @self.app.route("/api/v3/sessions/<sid>/findings", methods=["GET"])
        @self.require_auth
        def session_findings(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            sev = request.args.get("severity", "")
            src = request.args.get("source", "")
            out = []
            for f in s.get_findings()[:500]:
                if sev and f.severity.value != sev:
                    continue
                if src and src not in f.source:
                    continue
                out.append(f.to_dict())
            return jsonify({"findings": out, "count": len(out)})

        @self.app.route("/api/v3/sessions/<sid>/attack-paths", methods=["GET"])
        @self.require_auth
        def attack_paths(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from graph.attack_path import map_attack_paths
            return jsonify(map_attack_paths(s))

        @self.app.route("/api/v3/sessions/<sid>/kill-chain", methods=["GET"])
        @self.require_auth
        def kill_chain(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from graph.kill_chain_mapper import KillChainMapper
            return jsonify(KillChainMapper(s).map())

        @self.app.route("/api/v3/sessions/<sid>/reports", methods=["GET"])
        @self.require_auth
        def list_reports(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            rep = s.dir("report")
            files = [{"name": p.name, "size": p.stat().st_size}
                     for p in sorted(rep.glob("*")) if p.is_file()][:100]
            return jsonify({"reports": files})

        @self.app.route("/api/v3/sessions/<sid>/reports/<name>", methods=["GET"])
        @self.require_auth
        def download_report(sid, name):
            s, err = _session_or_404(sid)
            if err:
                return err
            p = (s.dir("report") / name).resolve()
            if s.dir("report").resolve() not in p.parents and p != (s.dir("report") / name):
                return jsonify({"error": "invalid path"}), 400
            if not p.is_file():
                return jsonify({"error": "not found"}), 404
            return send_file(str(p), as_attachment=True)

        @self.app.route("/api/v3/sessions/<sid>/pdf", methods=["POST"])
        @self.require_auth
        def build_pdf(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.pdf_report import build_pdf as _pdf
            try:
                p = _pdf(s)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return jsonify({"file": p.name, "size": p.stat().st_size})

        @self.app.route("/api/v3/sessions/<sid>/remediation", methods=["GET", "POST"])
        @self.require_auth
        def remediation(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules import pdf_report
            if request.method == "GET":
                return jsonify(pdf_report.remediation_summary(s))
            data = request.get_json() or {}
            try:
                rec = pdf_report.set_state(
                    s, data.get("finding_id", ""), data.get("state", "open"),
                    data.get("note", ""), getattr(request, "ops_user", "?"))
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            return jsonify(rec)

        @self.app.route("/api/v3/sessions/<sid>/verify", methods=["POST"])
        @self.require_auth
        def verify_session(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.verify import run_verify
            from modules.logger import get_logger
            return jsonify(run_verify(s, get_logger("verify")))

        @self.app.route("/api/v3/sessions/<sid>/enrich", methods=["POST"])
        @self.require_auth
        def enrich_session(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.intel_enrich import auto_enrich
            return jsonify(auto_enrich(s))

        @self.app.route("/api/v3/sessions/<sid>/loot", methods=["GET"])
        @self.require_auth
        def loot_view(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules import loot as _loot
            return jsonify(_loot.triage_session(s))

        @self.app.route("/api/v3/sessions/<sid>/exfil", methods=["GET", "POST"])
        @self.require_auth
        def exfil_view(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules import exfil_ledger
            if request.method == "GET":
                return jsonify(exfil_ledger.summary(s))
            data = request.get_json() or {}
            return jsonify(exfil_ledger.record(
                s, data.get("artifact", "?"), data.get("kind", "file"),
                int(data.get("size_bytes", 0)), data.get("channel", "https"),
                data.get("note", ""))), 201

        # ── C2 / payloads / system ──

        @self.app.route("/api/v3/payloads", methods=["GET"])
        @self.require_auth
        def payload_list():
            from modules.payloads import list_profiles
            return jsonify({"profiles": list_profiles()})

        @self.app.route("/api/v3/c2/overview", methods=["GET"])
        @self.require_auth
        def c2_overview():
            from ops import c2 as _c2
            return jsonify(_c2.overview())

        @self.app.route("/api/v3/c2/register", methods=["POST"])
        @self.require_auth
        def c2_register():
            from ops import c2 as _c2
            try:
                aid = _c2.register(request.get_json() or {})
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            return jsonify({"agent_id": aid}), 201

        @self.app.route("/api/v3/c2/task", methods=["POST"])
        @self.require_auth
        def c2_task():
            from ops import c2 as _c2
            data = request.get_json() or {}
            try:
                return jsonify(_c2.queue_task(
                    data.get("agent_id", ""),
                    data.get("command", ""),
                    data.get("command_type", "shell"))), 201
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        @self.app.route("/api/v3/c2/failover", methods=["POST"])
        @self.require_auth
        def c2_failover():
            from ops import c2 as _c2
            data = request.get_json() or {}
            try:
                return jsonify(_c2.failover(
                    data.get("primary", ""), data.get("backup1", ""),
                    data.get("backup2", "")))
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        @self.app.route("/api/v3/c2/listener/status", methods=["GET"])
        @self.require_auth
        def c2_listener_status():
            from ops import c2 as _c2
            return jsonify(_c2.listener_status())

        @self.app.route("/api/v3/c2/listener/start", methods=["POST"])
        @self.require_auth
        def c2_listener_start():
            from ops import c2 as _c2
            data = request.get_json() or {}
            try:
                return jsonify(_c2.listener_start(
                    data.get("host", "127.0.0.1"),
                    int(data.get("port", 4443)))), 201
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        @self.app.route("/api/v3/c2/listener/stop", methods=["POST"])
        @self.require_auth
        def c2_listener_stop():
            from ops import c2 as _c2
            try:
                return jsonify(_c2.listener_stop())
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        # ── Settings: API keys (masked values only; never plaintext) ──

        @self.app.route("/api/v3/settings/keys", methods=["GET"])
        @self.require_auth
        def settings_keys():
            from modules import apikeys
            return jsonify({"keys": apikeys.status(),
                            "file": str(apikeys.KEYS_FILE)})

        @self.app.route("/api/v3/settings/keys", methods=["POST"])
        @self.require_auth
        def settings_key_set():
            from modules import apikeys
            data = request.get_json() or {}
            name = str(data.get("name", ""))
            try:
                apikeys.set_key(name, str(data.get("value", "")))
            except KeyError as e:
                return jsonify({"error": str(e)}), 400
            entry = next((k for k in apikeys.status()
                          if k["name"] == name), None)
            return jsonify({"ok": True, "key": entry}), 201

        @self.app.route("/api/v3/settings/keys/<name>", methods=["DELETE"])
        @self.require_auth
        def settings_key_delete(name):
            from modules import apikeys
            try:
                removed = apikeys.delete_key(name)
            except KeyError as e:
                return jsonify({"error": str(e)}), 400
            return jsonify({"ok": True, "removed": removed})

        @self.app.route("/api/v3/preflight", methods=["GET"])
        @self.require_auth
        def preflight():
            from modules.preflight import check
            return jsonify(check())

        @self.app.route("/api/v3/scope", methods=["GET"])
        @self.require_auth
        def scope_status():
            return jsonify({"enabled": self.scope.enabled,
                            "allowed_targets": self.scope.allowed_targets})

        @self.app.route("/api/v3/scope/targets", methods=["POST"])
        @self.require_auth
        def scope_add():
            data = request.get_json() or {}
            try:
                out = self.scope.add_target(data.get("entry", ""))
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            self.ops_auth.audit("scope.add",
                                getattr(request, "ops_user", "?"),
                                "success", data.get("entry", ""))
            self.jobs.scope.reload()
            return jsonify(out), 201

        @self.app.route("/api/v3/scope/targets", methods=["DELETE"])
        @self.require_auth
        def scope_remove():
            data = request.get_json(silent=True) or {}
            out = self.scope.remove_target(data.get("entry", ""))
            self.ops_auth.audit("scope.remove",
                                getattr(request, "ops_user", "?"),
                                "success", data.get("entry", ""))
            self.jobs.scope.reload()
            return jsonify(out)

        @self.app.route("/api/v3/scope/enabled", methods=["POST"])
        @self.require_auth
        def scope_toggle():
            data = request.get_json() or {}
            out = self.scope.set_enabled(bool(data.get("enabled", True)))
            self.ops_auth.audit("scope.toggle",
                                getattr(request, "ops_user", "?"),
                                "success", str(out["enabled"]))
            self.jobs.scope.reload()
            return jsonify(out)

        @self.app.route("/api/v3/audit", methods=["GET"])
        @self.require_auth
        def audit_log():
            return jsonify({"audit": self.ops_auth.recent_audit(100),
                            "using_defaults": self.ops_auth.using_defaults()})

        @self.app.route("/api/v3/auth/logout", methods=["POST"])
        @self.require_auth
        def logout():
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            self.ops_auth.revoke(token)
            self.active_sessions.pop(token, None)
            return jsonify({"ok": True})

        # ── v2 toolkit (wires up all ardf_v2_* modules) ──

        @self.app.route("/api/v3/v2/toolkit", methods=["GET"])
        @self.require_auth
        def v2_toolkit():
            from ops import v2 as _v2
            return jsonify(_v2.toolkit_catalog())

        @self.app.route("/api/v3/v2/configs", methods=["GET"])
        @self.require_auth
        def v2_configs():
            from ops import v2 as _v2
            return jsonify({"configs": _v2.v2_configs()})

        @self.app.route("/api/v3/v2/coverage", methods=["GET"])
        @self.require_auth
        def v2_coverage():
            from ops import v2 as _v2
            return jsonify(_v2.tool_coverage())

        @self.app.route("/api/v3/v2/templates", methods=["GET"])
        @self.require_auth
        def v2_templates():
            from ops import v2 as _v2
            return jsonify({"templates": _v2.phishing_templates()})

        @self.app.route("/api/v3/v2/payload", methods=["POST"])
        @self.require_auth
        def v2_payload():
            from ops import v2 as _v2
            data = request.get_json() or {}
            try:
                out = _v2.generate_agent(
                    data.get("kind", ""), data.get("c2_server", ""),
                    int(data.get("c2_port", 443)), data.get("key", ""),
                    data.get("confirm_text", ""))
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            self.ops_auth.audit(
                "v2.payload", getattr(request, "ops_user", "?"),
                "success", out["kind"] + " -> " + out["c2_server"])
            code = out.pop("code")
            return jsonify({**out, "code_preview": code[:400]}), 201

        @self.app.route("/api/v3/sessions/<sid>/risk", methods=["POST"])
        @self.require_auth
        def session_risk(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from ops import v2 as _v2
            try:
                return jsonify(_v2.session_risk(s))
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # ── attack surface / opsec / payload repos ──

        @self.app.route("/api/v3/opsec/proxy", methods=["GET"])
        @self.require_auth
        def opsec_proxy():
            from modules import proxy_chain as _pc
            return jsonify(_pc.status())

        @self.app.route("/api/v3/opsec/tor-newnym", methods=["POST"])
        @self.require_auth
        def opsec_newnym():
            from modules import proxy_chain as _pc
            out = _pc.tor_new_circuit()
            self.ops_auth.audit("opsec.newnym",
                                getattr(request, "ops_user", "?"),
                                "success" if out.get("ok") else "failed")
            return jsonify(out)

        @self.app.route("/api/v3/opsec/audit", methods=["POST"])
        @self.require_auth
        def opsec_audit():
            from modules.opsec_audit import audit as _oa
            from modules.logger import get_logger
            data = request.get_json() or {}
            sid = data.get("session_id", "")
            s = None
            if sid:
                s, err = _session_or_404(sid)
                if err:
                    return err
            return jsonify(_oa(s, get_logger("opsec.audit")))

        @self.app.route("/api/v3/doh", methods=["GET"])
        @self.require_auth
        def doh_lookup():
            from modules.doh import doh_query
            from modules import proxy_chain as _pc
            host = request.args.get("host", "")
            if not host:
                return jsonify({"error": "need ?host="}), 400
            return jsonify(doh_query(host, request.args.get("type", "A"),
                                     proxy=_pc.current_proxy() or ""))

        @self.app.route("/api/v3/track-cover", methods=["GET"])
        @self.require_auth
        def track_cover_list():
            from modules.track_cover import _v2_capabilities, local_checklist
            return jsonify({"v2_capabilities": _v2_capabilities(),
                            "checklist": local_checklist()})

        @self.app.route("/api/v3/track-cover/generate", methods=["POST"])
        @self.require_auth
        def track_cover_gen():
            s, err = None, None
            data = request.get_json() or {}
            sid = data.get("session_id", "")
            if sid:
                s, err = _session_or_404(sid)
                if err:
                    return err
            if s is None:
                return jsonify({"error": "need session_id"}), 400
            from modules.track_cover import generate as _tcgen
            from modules.logger import get_logger
            return jsonify(_tcgen(s, data.get("kinds"),
                                  get_logger("trackcover"))), 201

        @self.app.route("/api/v3/sessions/<sid>/surface", methods=["GET"])
        @self.require_auth
        def surface_list(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.surface import build_candidates
            return jsonify({"candidates": build_candidates(s)})

        @self.app.route("/api/v3/sessions/<sid>/surface/validate", methods=["POST"])
        @self.require_auth
        def surface_validate(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.surface import run_surface_validate
            from modules.logger import get_logger
            data = request.get_json() or {}
            return jsonify(run_surface_validate(
                s, get_logger("surface"),
                int(data.get("limit", 20))))

        @self.app.route("/api/v3/sessions/<sid>/validate-one", methods=["POST"])
        @self.require_auth
        def validate_one(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.logger import get_logger
            data = request.get_json() or {}
            kind, url = data.get("kind", ""), data.get("url", "")
            table = {
                "xss": "modules.validate.xss.XSSValidator",
                "sqli": "modules.validate.sqli.SQLiValidator",
                "ssti": "modules.validate.ssti.SSTIValidator",
                "ssrf": "modules.validate.ssrf.SSRFValidator",
                "lfi": "modules.validate.lfi.LFIValidator",
                "redirect": "modules.validate.open_redirect.OpenRedirectValidator",
                "graphql": "modules.validate.graphql.GraphQLValidator",
                "cors": "modules.validate.cors.CORSValidator",
                "hostheader": "modules.validate.host_header.HostHeaderValidator",
                "jwt": "modules.validate.jwt.JWTValidator",
                "auth": "modules.validate.auth.AuthValidator",
            }
            ref = table.get(kind)
            if not ref or not url:
                return jsonify({"error": "need kind + url",
                                "kinds": sorted(table)}), 400
            import importlib
            mod_name, cls_name = ref.rsplit(".", 1)
            try:
                out = getattr(importlib.import_module(mod_name),
                              cls_name)(s, get_logger("validate")).validate(url)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return jsonify(out)

        @self.app.route("/api/v3/opsec", methods=["GET", "POST"])
        @self.require_auth
        def opsec():
            from modules import opsec_profiles as _op
            if request.method == "GET":
                return jsonify({**_op.current_profile(),
                                "profiles": sorted(_op.PROFILES)})
            data = request.get_json() or {}
            try:
                p = _op.apply_profile(data.get("profile", ""))
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            self.ops_auth.audit("opsec.profile",
                                getattr(request, "ops_user", "?"),
                                "success", p.name)
            return jsonify(p.to_dict())

        @self.app.route("/api/v3/payload-repos", methods=["GET"])
        @self.require_auth
        def payload_repos():
            from modules.payload_repos import catalog
            return jsonify({"repos": catalog()})

        @self.app.route("/api/v3/tampers", methods=["GET"])
        @self.require_auth
        def tampers():
            from modules.tamper import catalog as _tc
            return jsonify({"tampers": _tc()})

        # ── payload DB + fuzzer ──

        @self.app.route("/api/v3/payloaddb/stats", methods=["GET"])
        @self.require_auth
        def payloaddb_stats():
            from modules.payload_db import stats
            return jsonify(stats())

        @self.app.route("/api/v3/payloaddb/query", methods=["GET"])
        @self.require_auth
        def payloaddb_query():
            from modules.payload_db import query
            cat = request.args.get("category", "xss")
            try:
                limit = min(int(request.args.get("limit", 50)), 500)
            except ValueError:
                limit = 50
            return jsonify({"category": cat,
                            "payloads": query(cat, limit=limit)})

        @self.app.route("/api/v3/payloaddb/export", methods=["POST"])
        @self.require_auth
        def payloaddb_export():
            from modules.payload_db import export
            from pathlib import Path as _P
            data = request.get_json() or {}
            out = _P("output") / "payloads" / \
                f"{data.get('category', 'xss')}.txt"
            out.parent.mkdir(parents=True, exist_ok=True)
            path = export(data.get("category", "xss"), str(out),
                          int(data.get("limit", 2000)))
            return jsonify({"path": path, "size": _P(path).stat().st_size})

        @self.app.route("/api/v3/brute-lists", methods=["GET"])
        @self.require_auth
        def brute_lists():
            from modules.payload_db import brute_pair
            return jsonify(brute_pair())

        @self.app.route("/api/v3/fuzz", methods=["POST"])
        @self.require_auth
        def fuzz_run():
            from modules.fuzzer import PayloadFuzzer
            from modules.logger import get_logger
            data = request.get_json() or {}
            sid = data.get("session_id", "")
            s, err = (None, None)
            if sid:
                s, err = _session_or_404(sid)
                if err:
                    return err
            if s is None:
                return jsonify({"error": "need session_id"}), 400
            try:
                out = PayloadFuzzer(s, get_logger("fuzz")).run(
                    data.get("url") or s.meta.target,
                    data.get("category", "xss"),
                    min(int(data.get("max_requests", 60)), 500))
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            self.ops_auth.audit("fuzz", getattr(request, "ops_user", "?"),
                                "success", data.get("category", "xss"))
            return jsonify(out)

        # ── finding actions (validate / exploit / db-login) ──

        RECON_MODULES = {
            "wayback": "modules.recon.wayback",
            "dorkpack": "modules.recon.dorkpack",
            "subpermute": "modules.recon.subpermute",
            "subvalidate": "modules.recon.subvalidate",
            "cohosted": "modules.recon.cohosted",
            "asn": "modules.recon.asn_lookup",
            "s3": "modules.recon.s3_enum",
            "github": "modules.recon.github_recon",
            "jsminer": "modules.recon.js_miner",
            "waf": "modules.recon.waf_detect",
            "headers": "modules.recon.header_audit",
            "methods": "modules.recon.method_audit",
            "robots": "modules.recon.robots_parser",
            "subbrute": "modules.recon.subdomain_brute",
            "direnum": "modules.recon.dir_enum",
            "portfp": "modules.recon.port_fingerprint",
            "crawler": "modules.recon.crawler",
        }

        @self.app.route("/api/v3/sessions/<sid>/recon/<name>", methods=["POST"])
        @self.require_auth
        def recon_run(sid, name):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.logger import get_logger
            mod_name = RECON_MODULES.get(name)
            if not mod_name:
                return jsonify({"error": "unknown recon module",
                                "available": sorted(RECON_MODULES)}), 400
            import importlib
            try:
                fn = getattr(importlib.import_module(mod_name), "run")
                out = fn(s, s.meta.target, get_logger("recon." + name))
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            self.ops_auth.audit("recon." + name,
                                getattr(request, "ops_user", "?"),
                                "success", sid)
            return jsonify(out if isinstance(out, dict) else {"result": out})

        @self.app.route("/api/v3/chains", methods=["GET"])
        @self.require_auth
        def chains_list():
            from ops.chains import list_chains
            return jsonify({"chains": list_chains()})

        @self.app.route("/api/v3/chains/run", methods=["POST"])
        @self.require_auth
        def chains_run():
            from modules.logger import get_logger
            from ops.chains import run_chain
            data = request.get_json() or {}
            sid = data.get("session_id", "")
            s, err = (None, None)
            if sid:
                s, err = _session_or_404(sid)
                if err:
                    return err
            if s is None:
                return jsonify({"error": "need session_id"}), 400
            try:
                out = run_chain(s, data.get("chain", ""),
                                data.get("spec", {}) or {},
                                data.get("confirm_text", ""),
                                get_logger("chains"))
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            self.ops_auth.audit("chain.run",
                                getattr(request, "ops_user", "?"),
                                "success",
                                data.get("chain", ""))
            return jsonify(out)

        @self.app.route("/api/v3/sessions/<sid>/findings/actions", methods=["GET"])
        @self.require_auth
        def finding_actions(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from ops.actions import finding_actions as _fa
            fid = request.args.get("finding_id", "")
            f = next((x for x in s.get_findings() if x.id == fid), None)
            if f is None:
                return jsonify({"error": "finding not found"}), 404
            return jsonify({"actions": _fa(f)})

        @self.app.route("/api/v3/sessions/<sid>/actions", methods=["POST"])
        @self.require_auth
        def run_action(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.logger import get_logger
            from ops import actions as _ac
            data = request.get_json() or {}
            action, fid = data.get("action", ""), data.get("finding_id", "")
            f = next((x for x in s.get_findings() if x.id == fid), None)
            if f is None:
                return jsonify({"error": "finding not found"}), 404
            user = getattr(request, "ops_user", "?")
            log = get_logger("actions")
            try:
                if action == "validate":
                    out = _ac.run_validate(s, f, log)
                    code = 200
                elif action == "exploit":
                    out = _ac.run_exploit(s, f, data.get("confirm_text", ""), log)
                    code = 200
                elif action == "verify":
                    out = {"queued": True}
                    code = 200
                else:
                    return jsonify({"error": "unknown action"}), 400
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            self.ops_auth.audit(f"action.{action}", user, "success",
                                f"{sid}:{fid}")
            return jsonify(out), code

        @self.app.route("/api/v3/sessions/<sid>/db-probe", methods=["POST"])
        @self.require_auth
        def db_probe(sid):
            s, err = _session_or_404(sid)
            if err:
                return err
            from modules.logger import get_logger
            from ops.actions import run_db_login
            data = request.get_json() or {}
            if (data.get("confirm_text", "") or "").strip() != "CONFIRM":
                return jsonify({"error": "Tier-3: pass confirm_text='CONFIRM'"}), 403
            try:
                out = run_db_login(s, data.get("host", ""), int(data.get("port", 0)),
                                   data.get("service", ""), get_logger("actions"))
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            self.ops_auth.audit("action.db_login",
                                getattr(request, "ops_user", "?"),
                                "success",
                                f"{data.get('host')}:{data.get('port')}")
            return jsonify(out)

        @self.app.route("/api/v3/opsec/egress-verify", methods=["GET"])
        @self.require_auth
        def egress_verify():
            from modules import proxy_chain as _pc
            return jsonify(_pc.egress_verify())

        # ── Engagement-scoped offensive module runs ──
        @self.app.route("/api/v3/engagements/modules", methods=["GET"])
        @self.require_auth
        def engagement_modules():
            from ardf.offensive.base import OFFENSIVE_MODULES
            return jsonify({"modules": [
                {"id": module_id, **spec}
                for module_id, spec in OFFENSIVE_MODULES.items()
            ]})

        @self.app.route("/api/v3/engagements/<eid>", methods=["GET"])
        @self.require_auth
        def engagement_summary(eid):
            from ardf.offensive.base import EngagementStore
            try:
                out = EngagementStore().summary(eid)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            except FileNotFoundError:
                out = {"engagement": eid, "results": [], "logs": [],
                       "result_count": 0, "log_count": 0}
            return jsonify(out)

        @self.app.route("/api/v3/engagements/<eid>/run", methods=["POST"])
        @self.require_auth
        def engagement_run(eid):
            from ardf.offensive.base import EngagementStore, OFFENSIVE_MODULES
            data = request.get_json() or {}
            module_id = data.get("module", "")
            target = (data.get("target") or "").strip()
            facts = data.get("facts") or {}

            if module_id not in OFFENSIVE_MODULES:
                return jsonify({"error": "unknown module"}), 400
            if not target:
                return jsonify({"error": "target required"}), 400
            if not isinstance(facts, dict):
                return jsonify({"error": "facts must be a JSON object"}), 400
            try:
                eid = EngagementStore.sanitize(eid)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400

            ok, reason = self.scope.validate(target)
            if not ok:
                return jsonify({"error": reason}), 403

            spec = OFFENSIVE_MODULES[module_id]
            cmd = [
                sys.executable, "-m", spec["module"],
                "--target", target,
                "--engagement", eid,
                "--authorized-by", getattr(request, "ops_user", "operator"),
                "--facts-json", json.dumps(facts),
                "--json",
            ]
            if data.get("allow_destructive"):
                cmd.append("--allow-destructive")
            env = os.environ.copy()
            env["PYTHONPATH"] = (
                str(Path(__file__).parent) + os.pathsep + env.get("PYTHONPATH", "")
            )
            try:
                proc = subprocess.run(
                    cmd, cwd=str(Path(__file__).parent), env=env,
                    capture_output=True, text=True, timeout=120,
                )
            except subprocess.TimeoutExpired:
                return jsonify({"error": "module timed out"}), 504
            if proc.returncode != 0:
                message = (proc.stderr or "module failed").strip()[:2000]
                return jsonify({"error": message}), 400
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return jsonify({
                    "error": "module returned invalid JSON",
                    "stdout": proc.stdout[:2000],
                }), 500

            self.ops_auth.audit(
                "engagement.run",
                getattr(request, "ops_user", "?"),
                "success",
                f"{eid}:{module_id}",
            )
            self.log_request("POST", f"/api/v3/engagements/{eid}/run", "success")
            return jsonify(payload), 201

        @self.app.route("/api/v3/engagements/<eid>/file", methods=["GET"])
        @self.require_auth
        def engagement_file(eid):
            from ardf.offensive.base import EngagementStore
            relative = request.args.get("path", "")
            try:
                path = EngagementStore().read(eid, relative)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            except FileNotFoundError:
                return jsonify({"error": "not found"}), 404
            return send_file(str(path), as_attachment=True)

        @self.app.route("/api/v3/engagements/<eid>/download", methods=["GET"])
        @self.require_auth
        def engagement_download(eid):
            from ardf.offensive.base import EngagementStore
            try:
                archive = EngagementStore().zip(eid)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            except FileNotFoundError:
                return jsonify({"error": "not found"}), 404
            return send_file(str(archive), as_attachment=True,
                             download_name=f"{eid}.zip")

        @self.app.errorhandler(404)
        def not_found(e):
            return jsonify({"error": "Not found"}), 404

        @self.app.errorhandler(500)
        def server_error(e):
            self.logger.error(f"Server error: {e}")
            return jsonify({"error": "Internal server error"}), 500

    def require_auth(self, f):
        """Decorator to require authentication (ops tokens or legacy key)."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                token = request.args.get("token", "")  # downloads / EventSource
            user = self.ops_auth.check(token) if token else None
            if user:
                request.ops_user = user
            elif token and token in self.active_sessions:
                request.ops_user = "legacy"
            else:
                return jsonify({"error": "Unauthorized"}), 401

            self.log_request(request.method, request.path, "authenticated")
            return f(*args, **kwargs)

        return decorated_function

    def handle_login(self) -> Tuple[str, int]:
        """Handle login request (username/password preferred, key legacy)."""
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")
        key = data.get("key", "")

        if username and self.ops_auth.verify(username, password):
            out = self.ops_auth.issue(username)
            self.log_request("POST", "/api/v3/auth/login", "success")
            out["using_defaults"] = self.ops_auth.using_defaults()
            return jsonify(out), 200

        if key and hashlib.sha256(key.encode()).hexdigest() == hashlib.sha256(self.auth_key.encode()).hexdigest():
            token = hashlib.sha256(f"{key}{datetime.now().isoformat()}".encode()).hexdigest()
            self.active_sessions[token] = {
                "created": datetime.now().isoformat(),
                "expires": (datetime.now() + timedelta(hours=1)).isoformat()
            }
            self.log_request("POST", "/api/v3/auth/login", "success")
            return jsonify({
                "token": token,
                "expires": self.active_sessions[token]["expires"]
            }), 200
        else:
            self.ops_auth.audit("login", username or "?", "failed")
            self.log_request("POST", "/api/v3/auth/login", "failed")
            return jsonify({"error": "Invalid credentials"}), 401

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get dashboard summary data."""
        state = self.framework.get_framework_state()
        return {
            "version": "3.0.0",
            "status": "running" if state.get("initialized") else "initializing",
            "uptime": state.get("start_time"),
            "modules": {
                "loaded": state.get("modules_loaded", 0),
                "failed": state.get("modules_failed", 0),
                "total": state.get("modules_loaded", 0) + state.get("modules_failed", 0)
            },
            "endpoints": {
                "total": state.get("endpoints_registered", 0),
                "categories": len(self.framework.endpoints.get_categories())
            },
            "timestamp": datetime.now().isoformat()
        }

    def get_framework_stats(self) -> Dict[str, Any]:
        """Get detailed framework statistics."""
        state = self.framework.get_framework_state()
        endpoints = self.framework.endpoints
        
        return {
            "framework": {
                "version": "3.0.0",
                "initialized": state.get("initialized", False),
                "uptime": state.get("start_time")
            },
            "modules": {
                "total": state.get("modules_loaded", 0) + state.get("modules_failed", 0),
                "loaded": state.get("modules_loaded", 0),
                "failed": state.get("modules_failed", 0),
                "categories": len(state.get("modules_info", {}))
            },
            "endpoints": {
                "total": len(endpoints.endpoints),
                "by_category": endpoints.get_categories(),
                "methods": self._count_methods()
            },
            "api": {
                "total_requests": len(self.request_log),
                "authenticated_sessions": len(self.active_sessions)
            },
            "timestamp": datetime.now().isoformat()
        }

    def _count_methods(self) -> Dict[str, int]:
        """Count endpoints by HTTP method."""
        counts = {}
        for key in self.framework.endpoints.endpoints.keys():
            method = key.split(":")[0]
            counts[method] = counts.get(method, 0) + 1
        return counts

    def execute_user_endpoint(self) -> Tuple[str, int]:
        """Execute an endpoint requested by user."""
        data = request.get_json() or {}
        path = data.get("path", "")
        method = data.get("method", "GET")
        params = data.get("params", {})

        if not path:
            return jsonify({"error": "Missing path parameter"}), 400

        try:
            result = self.framework.execute_endpoint(path, method, **params)
            self.log_request(method, path, "success")
            return jsonify({"result": result}), 200
        except Exception as e:
            self.log_request(method, path, f"error: {str(e)}")
            return jsonify({"error": str(e)}), 500

    def log_request(self, method: str, path: str, status: str) -> None:
        """Log API request."""
        self.request_log.append({
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "path": path,
            "status": status
        })

        if len(self.request_log) > self.max_log_size:
            self.request_log = self.request_log[-self.max_log_size:]

    _WEB_DIR = Path(__file__).parent / "interface" / "web"

    def _serve_static(self, name: str, mimetype: str) -> Response:
        """Serve UI files from interface/web/ (login page needs app.js)."""
        path = (self._WEB_DIR / name).resolve()
        if not path.is_relative_to(self._WEB_DIR.resolve()) or not path.is_file():
            return Response("not found", status=404, mimetype="text/plain")
        return Response(path.read_text(), mimetype=mimetype, headers={
            "Cache-Control": "no-store, must-revalidate",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })

    def run(self) -> None:
        """Start the dashboard server."""
        self.logger.info(f"Starting ARDF v3 Dashboard on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=self.debug)


def run_dashboard(framework, host: str = "0.0.0.0", port: int = 5000, debug: bool = False) -> None:
    """Helper function to run dashboard."""
    dashboard = ARDFv3DashboardAPI(framework, host, port, debug)
    dashboard.run()


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from ardf_v3_framework import get_framework

    framework = get_framework()
    framework.initialize()
    run_dashboard(framework, debug=True)
