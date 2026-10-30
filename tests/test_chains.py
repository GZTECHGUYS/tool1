"""Chain precision tests — localhost stub + closed-port DB.

Proves: chains stop (never empty attacks), CONFIRM enforced, blocklist
holds, step evidence recorded.
"""
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

import modules.session as sm
from modules.session import (Session, SessionMeta, SessionStatus, Mode,
                             Finding, SeverityLevel)


class _Stub(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("id", [""])[-1])
        if "'" in val and "union" not in val.lower():
            body = "ERROR 1064 mysql syntax error near ''"
        elif "union" in val.lower() and val.lower().count("null") >= 2:
            body = "<html>union-data-marker</html>"
        else:
            body = "<html>item page</html>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def stub_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}/item?id=1"
    srv.shutdown()


def _sess(tmp_path, name="chain"):
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None
    now = datetime.now().isoformat()
    s = Session(SessionMeta(session_id=name, name=name, target="127.0.0.1",
                            mode=Mode.RED, status=SessionStatus.CREATED,
                            created_at=now, updated_at=now))
    s.save()
    return s


class TestChains:
    def test_catalog(self):
        from ops.chains import list_chains, CHAINS
        assert len(list_chains()) == len(CHAINS) == 8
        assert "db_mssql" in CHAINS and "sqli_param" in CHAINS

    def test_confirm_enforced(self, tmp_path):
        from ops.chains import run_chain
        from modules.logger import get_logger
        with pytest.raises(PermissionError):
            run_chain(_sess(tmp_path), "db_mssql",
                      {"host": "127.0.0.1", "port": 1433,
                       "service": "mssql", "target": "127.0.0.1"},
                      "nope", get_logger("t"))

    def test_sqli_chain_precise_stop(self, tmp_path, stub_url):
        """detect ok -> boolean differential false on stub -> STOPS (no empty follow-ups)."""
        from ops.chains import run_chain
        from modules.logger import get_logger
        s = _sess(tmp_path, "c1")
        out = run_chain(s, "sqli_param", {"url": stub_url,
                                          "target": "127.0.0.1"},
                        "CONFIRM", get_logger("t"))
        steps = [t["step"] for t in out["transcript"]]
        assert steps[0] == "detect_params" and out["transcript"][0]["ok"] is True
        assert out["stopped"] is True and out["steps_ok"] == 1

    def test_db_chain_closed_port_stops(self, tmp_path):
        from ops.chains import run_chain
        from modules.logger import get_logger
        s = _sess(tmp_path, "c2")
        out = run_chain(s, "db_postgres",
                        {"host": "127.0.0.1", "port": 15432,
                         "service": "postgres", "target": "127.0.0.1"},
                        "CONFIRM", get_logger("t"))
        steps = [(t["step"], t["ok"]) for t in out["transcript"]]
        assert steps[0][0] == "banner"
        assert ("default_creds", False) in steps
        assert out["stopped"] is True

    def test_blocklist(self):
        from ops.chains import _nse
        assert _nse("h", 1, "ms-sql-xp-cmdshell").get("blocked") is True
        assert _nse("h", 1, "mysql-dump-hashes").get("blocked") is True

    def test_actions_dispatch_db(self, tmp_path):
        from ops.actions import run_exploit
        from modules.logger import get_logger
        s = _sess(tmp_path, "c3")
        f = Finding(source="recon.normal",
                    title="Port 15432/tcp open (postgresql)",
                    severity=SeverityLevel.INFO, host="127.0.0.1",
                    tags=["port", "db"])
        out = run_exploit(s, f, "CONFIRM", get_logger("t"))
        assert out["chain"] == "db_postgres" and out["stopped"] is True
