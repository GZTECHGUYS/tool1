/* ARDF Ops Console — plain ES2017, no nested template literals. */
(function () {
  "use strict";

  window.onerror = function (m) {
    var v = document.getElementById("view");
    if (v && !v.dataset.failed) {
      v.dataset.failed = "1";
      v.innerHTML = '<div class="card"><h3>Client error</h3><pre>' +
        String(m) + "</pre><p>Press F12 for details.</p></div>";
    }
  };

  window.addEventListener("unhandledrejection", function (e) {
    var msg = (e.reason && e.reason.message) || e.reason || "unknown error";
    try { toast("client error: " + msg, "err"); } catch (x) {}
  });

  var store = (function () {
    try {
      localStorage.setItem("__t", "1");
      localStorage.removeItem("__t");
      return localStorage;
    } catch (e) {
      var mem = {};
      return {
        getItem: function (k) { return (k in mem) ? mem[k] : null; },
        setItem: function (k, v) { mem[k] = String(v); },
        removeItem: function (k) { delete mem[k]; },
      };
    }
  })();

  function _themeFromUrl() {
    try {
      var m = /[?&]theme=(tui|neon)(?:&|$)/.exec(location.search || "");
      return m ? m[1] : "";
    } catch (e) {
      return "";
    }
  }

  var T = store.getItem("ardf_token");
  var USER = store.getItem("ardf_user") || "";
  var THEME = _themeFromUrl() || store.getItem("ardf_theme") || "tui";
  var CUR = "overview";
  var SID = "";
  var _loggingOut = false;
  var _eventCount = 0;
  var _bootSettled = false;
  var _bootTimer = null;

  function _pad4(n) {
    var s = String(n || 0);
    while (s.length < 4) s = "0" + s;
    return s;
  }

  function applyTheme(name) {
    THEME = name === "neon" ? "neon" : "tui";
    try { store.setItem("ardf_theme", THEME); } catch (e) {}
    var body = document.body;
    if (body && body.classList) {
      body.classList.toggle("theme-tui", THEME === "tui");
      body.classList.toggle("theme-neon", THEME === "neon");
    }
    var label = document.getElementById("theme-label");
    if (label) label.textContent = THEME === "tui" ? "TUI" : "NEON";
  }

  function toggleTheme() {
    applyTheme(THEME === "tui" ? "neon" : "tui");
    toast("theme: " + THEME.toUpperCase(), "ok");
  }

  function esc(s) {
    return String(s === undefined || s === null ? "" : s).replace(
      /[&<>"]/g,
      function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
      }
    );
  }

  function showLogin() {
    var lo = document.getElementById("login-overlay");
    var shell = document.getElementById("app-shell");
    if (lo) lo.classList.remove("hidden");
    if (shell) shell.classList.add("hidden");
    var u = document.getElementById("u");
    if (u) { try { u.focus(); } catch (e) {} }
  }

  function showApp() {
    var lo = document.getElementById("login-overlay");
    var shell = document.getElementById("app-shell");
    if (lo) lo.classList.add("hidden");
    if (shell) shell.classList.remove("hidden");
    var uh = document.getElementById("user-hud");
    if (uh) uh.textContent = USER || "operator";
  }

  function login() {
    var u = document.getElementById("u").value;
    var p = document.getElementById("p").value;
    var err = document.getElementById("lerr");
    if (err) err.textContent = "";
    api("POST", "/api/v3/auth/login", { username: u, password: p }).then(function (r) {
      if (r.d && r.d.token) {
        store.setItem("ardf_token", r.d.token);
        store.setItem("ardf_user", r.d.user || u || "operator");
        location.reload();
      } else if (err) {
        err.textContent = (r.d && r.d.error) || "link rejected — check credentials";
      }
    }).catch(function (e) {
      if (err) err.textContent = String(e && e.message || e);
    });
  }

  function toast(msg, kind) {
    var t = document.getElementById("toast");
    if (!t) return;
    t.textContent = msg;
    t.className = "toast" + (kind ? " " + kind : "");
    t.classList.remove("hidden");
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.classList.add("hidden"); }, 3800);
  }
  var EV_MAP = {
    "job.queued": "jobs", "job.started": "jobs", "job.complete": "jobs",
    "job.failed": "jobs", "job.killed": "jobs",
    "approval.pending": "approvals", "approval.decided": "approvals",
    "finding.new": "findings",
    "c2.agent.registered": "c2", "c2.agent.task": "c2", "c2.failover": "c2",
  };

  // ── live terminal (SSE-fed event console) ──────────────
  var _termLines = [];
  var TERM_MAX = 400;

  function _termFmt(ev) {
    var ts = "";
    try { ts = new Date().toISOString().slice(11, 19); } catch (e) {}
    var evData = ev.data || {};
    var host = evData.target || evData.host || "";
    var what = evData.title || evData.playbook || evData.message ||
      evData.chain || evData.agent_id || "";
    if (ev.type === "approval.pending") {
      what = "approve in Approvals tab: " + what;
    }
    return "[" + ts + "] " + ev.type + (host ? " " + host : "") +
      (what ? "  " + what : "");
  }

  function _setTicker(text) {
    var el = document.getElementById("ticker");
    if (!el) return;
    el.textContent = text;
    el.style.animation = "none";
    void el.offsetWidth;
    el.style.animation = "";
  }

  function _streamState(state) {
    var el = document.getElementById("stream-state");
    if (!el) return;
    el.textContent = state;
    el.className = "hud-value " +
      (state === "LIVE" ? "live" : state === "LOST" ? "dead" : "dim");
    var side = document.getElementById("side-state");
    if (side) side.textContent = state === "LIVE" ? "LINK READY" :
      state === "LOST" ? "LINK LOST" : "SYNCING";
  }

  function _bumpEvent() {
    _eventCount++;
    var c = document.getElementById("event-count");
    if (c) c.textContent = _eventCount + " EV";
    var f = document.getElementById("footer-events");
    if (f) f.textContent = String(_eventCount);
  }

  function _termLine(ev) {
    _termLines.push(_termFmt(ev));
    if (_termLines.length > TERM_MAX) _termLines.splice(0, _termLines.length - TERM_MAX);
    _bumpEvent();
    _setTicker(_termFmt(ev));
    var el = document.getElementById("termout");
    if (el && CUR === "term") {
      el.textContent = _termLines.join("\n");
      el.scrollTop = el.scrollHeight;
    }
  }

  function termClear() {
    _termLines = [];
    var el = document.getElementById("termout");
    if (el) el.textContent = "";
  }

  var _evReset = null;
  var _lastEvId = 0;

  function _liveView(tab) {
    if (CUR === tab) go(tab);
  }

  function _navBadge(tab, count) {
    var el = document.getElementById("badge-" + tab);
    if (!el) {
      var nav = document.getElementById("nav");
      if (!nav) return;
      var item = nav.querySelector('[data-tab="' + tab + '"]');
      if (!item) return;
      el = document.createElement("span");
      el.id = "badge-" + tab;
      el.className = "badge err";
      el.style.cssText = "margin-left:4px;display:none";
      item.appendChild(el);
    }
    el.textContent = count;
    el.style.display = count > 0 ? "inline-flex" : "none";
  }

  function tabTitle(tab) {
    for (var i = 0; i < TABS.length; i++) {
      if (TABS[i][0] === tab) return TABS[i][1];
    }
    return tab;
  }

  function _refreshApprovals() {
    api("GET", "/api/v3/approvals").then(function (r) {
      var list = (r.d && r.d.approvals) || [];
      var pending = 0;
      for (var i = 0; i < list.length; i++) {
        if (list[i].status === "pending") pending++;
      }
      _navBadge("approvals", pending);
      if (CUR === "approvals") go("approvals");
    });
  }

  function _handleEvent(ev) {
    var tab = EV_MAP[ev.type];
    if (ev.type === "finding.new") {
      var sev = (ev.data && ev.data.severity) || "";
      if (sev === "critical" || sev === "high") {
        toast("[" + sev + "] " + (ev.data && ev.data.title || "new finding"),
              sev === "critical" ? "err" : "warn");
      }
      _liveView("findings");
      _liveView("graph");
      return;
    }
    if (ev.type === "approval.pending" || ev.type === "approval.decided") {
      _refreshApprovals();
      return;
    }
    if (ev.type === "job.failed") {
      toast("job failed: " + (ev.data && ev.data.job_id || ""), "err");
    }
    if (!tab) return;
    _liveView(tab);
  }

  function _connectStream() {
    if (!T || _evReset) return;
    var src;
    try {
      src = new EventSource("/api/v3/events/stream?token=" + T +
                            "&since=" + _lastEvId);
    } catch (e) {
      return;
    }
    src.onopen = function () { _streamState("LIVE"); };
    src.onmessage = function (m) {
      try {
        var ev = JSON.parse(m.data);
        if (ev.id && ev.id <= _lastEvId) return;
        if (ev.id) _lastEvId = ev.id;
        _termLine(ev);
        _handleEvent(ev);
      } catch (e) { /* malformed line — ignore */ }
    };
    src.onerror = function () {
      _streamState("LOST");
      if (src.readyState === 2) {  // CLOSED: server gone or auth died
        src.close();
        _evReset = null;
        window.setTimeout(function () {
          if (T) { _streamState("SYNC"); _connectStream(); }
        }, 15000);
      }
    };
    _evReset = src;
  }

  function _fallbackPoll() {
    if (!T) return;
    api("GET", "/api/v3/approvals").then(function (r) {
      var list = (r.d && r.d.approvals) || [];
      var pending = 0;
      for (var i = 0; i < list.length; i++) {
        if (list[i].status === "pending") pending++;
      }
      _navBadge("approvals", pending);
    });
    api("GET", "/api/v3/jobs").then(function (r) {
      var list = (r.d && r.d.jobs) || [];
      var active = 0;
      for (var i = 0; i < list.length; i++) {
        var st = list[i].status;
        if (st === "running" || st === "queued" || st === "waiting_approval") active++;
      }
      _navBadge("jobs", active);
    });
  }

  function _authFail() {
    if (_loggingOut) return;
    _loggingOut = true;
    store.removeItem("ardf_token");
    store.removeItem("ardf_user");
    T = "";
    if (_evReset) {
      try { _evReset.close(); } catch (e) { /* already closed */ }
      _evReset = null;
    }
    showLogin();
    toast("session expired — re-authenticate", "warn");
  }

  function logout() {
    if (_loggingOut) return;
    _loggingOut = true;
    api("POST", "/api/v3/auth/logout").then(
      function () { store.removeItem("ardf_token"); store.removeItem("ardf_user"); location.reload(); },
      function () { store.removeItem("ardf_token"); store.removeItem("ardf_user"); location.reload(); }
    );
  }

  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { Authorization: "Bearer " + T, "Content-Type": "application/json" },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        // Do not recurse through the logout endpoint: a 401 there used to
        // call logout() again forever.
        if (r.status === 401 && path !== "/api/v3/auth/logout" &&
            path !== "/api/v3/auth/login") _authFail();
        return { d: d, status: r.status };
      });
    });
  }

  var TABS = [
    ["overview", "Overview", "COMMAND", "◉"],
    ["dash", "System", "COMMAND", "▤"],
    ["sessions", "Sessions", "COMMAND", "▣"],
    ["jobs", "Jobs", "OPERATIONS", "⚙"],
    ["approvals", "Approvals", "OPERATIONS", "✓"],
    ["modules", "Module Grid", "OPERATIONS", "▦"],
    ["attacks", "Attack Runner", "OPERATIONS", "⌁"],
    ["chains", "Attack Chains", "OPERATIONS", "⇉"],
    ["recon", "Recon+", "OPERATIONS", "◎"],
    ["surface", "Surface", "OPERATIONS", "◇"],
    ["findings", "Findings", "INTELLIGENCE", "◈"],
    ["graph", "Attack Graph", "INTELLIGENCE", "⌗"],
    ["reports", "Reports", "INTELLIGENCE", "▥"],
    ["opsec", "OPSEC", "DEFENSE", "◐"],
    ["preflight", "Preflight", "DEFENSE", "✚"],
    ["c2", "C2", "ARSENAL", "⌬"],
    ["payloads", "Payloads", "ARSENAL", "▧"],
    ["v2", "V2 Toolkit", "ARSENAL", "⧉"],
    ["term", "Terminal", "SYSTEM", "▸"],
    ["settings", "Settings", "SYSTEM", "⚒"],
  ];

  function nav() {
    var h = "";
    var last = "";
    for (var i = 0; i < TABS.length; i++) {
      var tab = TABS[i];
      if (tab[2] !== last) {
        h += '<div class="nav-group">' + esc(tab[2]) + "</div>";
        last = tab[2];
      }
      var cls = tab[0] === CUR ? "nav-item active" : "nav-item";
      h += '<div class="' + cls + '" data-tab="' + tab[0] +
        '" onclick="go(\'' + tab[0] + "')\">" +
        '<span class="ni" aria-hidden="true">' + esc(tab[3]) + "</span>" +
        '<span class="nl">' + esc(tab[1]) + "</span></div>";
    }
    document.getElementById("nav").innerHTML = h;
  }

  function go(t) {
    CUR = t;
    nav();
    var v = document.getElementById("view");
    if (v) {
      v.style.animation = "none";
      void v.offsetWidth;
      v.style.animation = "";
    }
    function failed(e) {
      document.getElementById("view").innerHTML =
        '<div class="card"><h3>View failed</h3><pre>' +
        esc(e && e.stack || e) + "</pre></div>";
    }
    var fn = views[t];
    if (!fn) {
      failed("unknown view: " + t);
      return Promise.resolve();
    }
    try {
      var out = fn();
      if (out && typeof out.catch === "function") return out.catch(failed);
      return Promise.resolve(out);
    } catch (e) {
      failed(e);
      return Promise.resolve();
    }
  }

  function setTitle(t, sub) {
    document.getElementById("title").textContent = t;
    var s = document.getElementById("subtitle");
    if (s) s.textContent = sub || "ops console · live telemetry";
  }
  function setView(h) { document.getElementById("view").innerHTML = h; }

  function sevCell(f) {
    return '<td class="sev-' + esc(f.severity) + '">' + esc(f.severity) + "</td>";
  }

  function _num(n) {
    n = Number(n || 0);
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "k";
    return String(n);
  }

  function _sevBars(by) {
    var keys = ["critical", "high", "medium", "low", "info"];
    var max = 1;
    for (var i = 0; i < keys.length; i++) max = Math.max(max, Number(by[keys[i]] || 0));
    var h = '<div class="bars">';
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      var v = Number(by[k] || 0);
      var pct = Math.max(v ? 3 : 0, Math.round(v / max * 100));
      h += '<div class="bar-row"><span class="sev-' + k + '">' + k + "</span>" +
        '<div class="bar-track"><div class="bar-fill ' + k +
        '" style="width:' + pct + '%"></div></div><b>' + _num(v) + "</b></div>";
    }
    return h + "</div>";
  }

  function _eventRows(events) {
    if (!events || !events.length) {
      return '<div class="event-empty">No events yet. Start a playbook or run a module.</div>';
    }
    var h = '<div class="event-list">';
    for (var i = events.length - 1; i >= 0; i--) {
      var ev = events[i] || {};
      var d = ev.data || {};
      var what = d.title || d.playbook || d.message || d.attack ||
        d.task || d.agent_id || d.job_id || "";
      var ts = _pad4(ev.id);
      h += '<div class="event-item"><span class="event-time">#' + esc(ts) +
        '</span><span><span class="event-type">' + esc(ev.type || "?") +
        '</span> <span class="event-detail">' + esc(String(what).slice(0, 90)) +
        "</span></span></div>";
    }
    return h + "</div>";
  }

  function _applyScope(scope) {
    scope = scope || {};
    var b = document.getElementById("scopebadge");
    if (b) {
      if (scope.enabled) {
        b.textContent = "SCOPE ON · " +
          (scope.allowed_targets || []).length + " RULES";
        b.className = "badge ok";
      } else {
        b.textContent = "SCOPE OFF";
        b.className = "badge warn";
      }
    }
    var fs = document.getElementById("footer-scope");
    if (fs) fs.textContent = scope.enabled ? "GUARDED" : "OPEN";
  }

  function _phasePills(by) {
    var h = '<div class="pill-row">';
    var keys = Object.keys(by || {});
    keys.sort();
    for (var i = 0; i < keys.length; i++) {
      h += '<span class="pill"><b>' + esc(keys[i]) + "</b> " +
        esc(by[keys[i]]) + "</span>";
    }
    return h + "</div>";
  }

  var views = {
    overview: function () {
      return api("GET", "/api/v3/dashboard/telemetry").then(function (r) {
        var d = r.d || {};
        var f = d.findings || { by_severity: {} };
        var s = d.sessions || {};
        var j = d.jobs || {};
        var a = d.approvals || {};
        var scope = d.scope || {};
        var atk = d.attacks || {};
        var mods = d.modules || {};
        var ep = d.endpoints || {};
        var stream = d.stream || {};
        setTitle("Overview", "command deck · live telemetry");
        var h = '<div class="stat-grid">' +
          '<div class="stat accent-cyan"><div class="stat-label">Sessions</div>' +
          '<div class="stat-value">' + _num(s.total) + '</div>' +
          '<div class="stat-sub">' + _num(s.active) + ' active</div></div>' +
          '<div class="stat accent-magenta"><div class="stat-label">Findings</div>' +
          '<div class="stat-value">' + _num((f.total)) + '</div>' +
          '<div class="stat-sub">risk score ' + esc(f.risk || 0) + '</div></div>' +
          '<div class="stat accent-amber"><div class="stat-label">Active jobs</div>' +
          '<div class="stat-value">' + _num(j.active) + '</div>' +
          '<div class="stat-sub">' + _num(j.total) + ' total</div></div>' +
          '<div class="stat accent-lime"><div class="stat-label">Approval gates</div>' +
          '<div class="stat-value">' + _num(a.pending) + '</div>' +
          '<div class="stat-sub">' + _num(atk.total) + ' attack modules</div></div>' +
          "</div>";

        h += '<div class="overview-grid">' +
          '<div class="overview-stack">' +
          '<div class="card"><h3>System integrity</h3><div class="radar-wrap">' +
          '<div class="radar"><div class="radar-sweep"></div>' +
          '<span class="radar-blip"></span><span class="radar-blip"></span>' +
          '<span class="radar-blip"></span></div>' +
          '<div class="radar-readout">' +
          '<div class="readout-row"><span>node state</span><b class="good">ONLINE</b></div>' +
          '<div class="readout-row"><span>stream</span><b class="' +
          (stream.last_id ? "good" : "") + '">' + _num(stream.last_id) + ' ev</b></div>' +
          '<div class="readout-row"><span>modules</span><b>' + _num(mods.loaded) +
          ' ok / ' + _num(mods.failed) + ' fail</b></div>' +
          '<div class="readout-row"><span>api routes</span><b>' +
          _num(ep.api_routes) + '</b></div>' +
          '<div class="readout-row"><span>preflight</span><b class="' +
          (d.preflight_ready === false ? "bad" : "good") + '">' +
          (d.preflight_ready === null || d.preflight_ready === undefined ? "n/a" :
            d.preflight_ready ? "READY" : "MISSING DEPS") + '</b></div>' +
          '<div class="readout-row"><span>scope guard</span><b class="' +
          (scope.enabled ? "good" : "bad") + '">' +
          (scope.enabled ? "ON · " + _num(scope.targets) + " rules" : "OFF") +
          '</b></div></div></div></div>' +
          '<div class="card"><h3>Severity load <span class="badge info">' +
          _num(f.total) + ' findings</span></h3>' + _sevBars(f.by_severity || {}) +
          "</div></div>" +
          '<div class="overview-stack">' +
          '<div class="card"><h3>Mission control</h3>' +
          '<div class="row"><input id="ov-target" placeholder="authorized target (in scope)" style="flex:1 1 180px">' +
          '<select id="ov-pb"><option value="passive">passive</option>' +
          '<option value="web">web</option><option value="full">full</option>' +
          '<option value="recon_boss">recon_boss</option>' +
          '<option value="purple_team">purple_team</option></select></div>' +
          '<div class="quick-grid"><button class="button button-primary" onclick="ovQuick()">Run playbook</button>' +
          '<button class="button" onclick="go(\'modules\')">Module grid</button>' +
          '<button class="button button-ghost" onclick="go(\'sessions\')">Sessions</button>' +
          '<button class="button button-ghost" onclick="go(\'term\')">Live terminal</button></div>' +
          '<div style="margin-top:12px">' + _phasePills(atk.by_phase || {}) + "</div></div>" +
          '<div class="card"><h3>Event stream <span class="badge">' +
          _num(stream.subscribers) + ' subscribers</span></h3>' +
          _eventRows(d.recent_events) + "</div></div></div>";
        setView(h);
      });
    },

    modules: function () {
      return api("GET", "/api/v3/attacks").then(function (r) {
        window.__modlist = (r.d && r.d.attacks) || [];
        window.__modsel = null;
        window.__modfilter = { phase: "ALL", q: "" };
        setTitle("Module Grid", "P1 / P2 / P3 · tier-gated execution");
        setView(
          '<div class="runner">' +
          '<div class="card"><h3>Module grid <span class="badge info" id="mod-count">' +
          window.__modlist.length + " modules</span></h3>" +
          '<div class="filterbar" id="mod-phases">' +
          '<button class="button active" data-phase="ALL" onclick="modFilter(\'ALL\')">ALL</button>' +
          '<button class="button" data-phase="P1" onclick="modFilter(\'P1\')">P1</button>' +
          '<button class="button" data-phase="P2" onclick="modFilter(\'P2\')">P2</button>' +
          '<button class="button" data-phase="P3" onclick="modFilter(\'P3\')">P3</button>' +
          '<button class="button" data-phase="T1" onclick="modFilter(\'T1\')">T1</button>' +
          '<button class="button" data-phase="T2" onclick="modFilter(\'T2\')">T2</button>' +
          '<button class="button" data-phase="T3" onclick="modFilter(\'T3\')">T3</button>' +
          "</div>" +
          '<input id="modq" placeholder="filter id, title, summary…" style="width:100%;margin:0 0 12px" oninput="modSearch()">' +
          '<div id="modgrid" class="module-grid"></div></div>' +
          '<div class="card"><h3>Selected module</h3>' +
          '<div id="moddetail"><p class="muted">Select a card to load its runner.</p></div>' +
          '<div class="row" style="margin-top:12px">' +
          '<input id="mod-target" placeholder="target override (blank = session target)" style="flex:1 1 180px">' +
          '<input id="mod-confirm" placeholder="APPROVE / CONFIRM" style="flex:0 1 150px"></div>' +
          '<div class="row"><button class="button" onclick="modRun(\'plan\')">Plan (safe)</button>' +
          '<button class="button danger" onclick="modRun(\'exec\')">Execute (gated)</button>' +
          '<button class="button button-ghost" onclick="go(\'attacks\')">Legacy runner</button></div>' +
          '<pre id="mod-out">—</pre></div></div>'
        );
        modRender();
        if (SID) {
          api("GET", "/api/v3/sessions/" + SID).then(function (sr) {
            var body = sr.d.session || sr.d || {};
            var meta = body.meta || {};
            var box = document.getElementById("mod-target");
            if (box && meta.target && !box.value) box.value = meta.target;
          });
        }
      });
    },

    term: function () {
      setTitle("Terminal");
      var h = '<div class="card"><h3>Live console</h3>' +
        '<div class="row"><button class="button" onclick="termClear()">' +
        "Clear</button></div>" +
        '<pre id="termout" style="background:#0a0e27;color:#9fe;' +
        "padding:10px;max-height:60vh;overflow:auto;min-height:30vh\">" +
        esc(_termLines.join("\n")) + "</pre></div>";
      h += '<pre style="opacity:.7">live event feed. job stdout: Jobs tab ' +
        "-> Live. exploit results appear in Findings -> exploit.</pre>";
      setView(h);
      return Promise.resolve();
    },
    dash: function () {
      var sum, scope;
      return api("GET", "/api/v3/dashboard/summary").then(function (r) {
        sum = r.d;
        return api("GET", "/api/v3/scope");
      }).then(function (r2) {
        scope = r2.d;
        setTitle("Dashboard");
        var targets = (scope.allowed_targets || []).map(function (t) {
          return "<tr><td>" + esc(t) + "</td>" +
            '<td><button class="button danger" data-entry="' + esc(t) +
            '" onclick="scopedel(this.dataset.entry)">Remove</button></td></tr>';
        }).join("");
        setView(
          '<div class="card"><h3>Framework</h3><table>' +
          "<tr><th>Status</th><td>" + esc(sum.status) + "</td></tr>" +
          "<tr><th>Modules</th><td>" + sum.modules.loaded + " loaded / " +
          sum.modules.failed + " failed</td></tr>" +
          "<tr><th>Endpoints</th><td>" + sum.endpoints.total + " in " +
          sum.endpoints.categories + " categories</td></tr>" +
          "</table></div>" +
          '<div class="card"><h3>Scope guardrail ' +
          (scope.enabled ? '<span class="badge ok">ON</span>' : '<span class="badge warn">OFF</span>') +
          '</h3><div class="row"><button class="button" onclick="scopetoggle()">' +
          (scope.enabled ? "Disable" : "Enable") + "</button>" +
          '<input id="sadd" placeholder="add target: host, CIDR or .suffix">' +
          '<button class="button" onclick="scopeadd()">Add target</button></div>' +
          "<table>" + targets + "</table></div>" +
          '<div class="card"><h3>Quick start</h3><div class="row">' +
          '<input id="qtarget" placeholder="target (in scope)">' +
          '<select id="qpb"><option value="passive">passive</option>' +
          '<option value="web">web</option><option value="full">full</option>' +
          '<option value="recon_boss">recon_boss</option></select>' +
          '<button class="button" onclick="quick()">Run playbook</button>' +
          "</div></div>"
        );
      });
    },

    sessions: function () {
      return api("GET", "/api/v3/sessions").then(function (r) {
        var list = r.d.sessions || [];
        setTitle("Sessions");
        var h =
          '<div class="card"><h3>New session</h3><div class="row">' +
          '<input id="nt" placeholder="target">' +
          '<select id="nm"><option>full</option><option>red</option>' +
          "<option>blue</option></select>" +
          '<button class="button" onclick="newsess()">Create</button>' +
          "</div></div>" +
          '<div class="card"><h3>Existing (' + list.length + ")</h3><table>" +
          "<tr><th>ID</th><th>Target</th><th>Status</th><th>Findings</th><th></th></tr>";
        for (var i = 0; i < list.length; i++) {
          var s = list[i];
          h += "<tr><td>" + esc(s.session_id) + "</td><td>" + esc(s.target) +
            "</td><td>" + esc(s.status) + "</td><td>" + esc(s.findings_count) +
            '</td><td><button class="button" onclick="pick(\'' +
            esc(s.session_id) + "')\">Open</button> " +
            '<button class="button danger" onclick="delsess(\'' +
            esc(s.session_id) + "')\">Delete</button></td></tr>";
        }
        setView(h + "</table></div>");
      });
    },

    jobs: function () {
      return api("GET", "/api/v3/jobs").then(function (r) {
        var list = r.d.jobs || [];
        setTitle("Jobs");
        var h = '<div class="card"><h3>Jobs (' + list.length + ")</h3><table>" +
          "<tr><th>ID</th><th>Playbook</th><th>Target</th><th>Status</th><th></th></tr>";
        for (var i = 0; i < list.length; i++) {
          var j = list[i];
          h += "<tr><td>" + esc(j.id) + "</td><td>" + esc(j.playbook) +
            "</td><td>" + esc(j.target) + '</td><td><span class="badge">' +
            esc(j.status) + '</span></td><td><button class="button" onclick="joblog(\'' +
            esc(j.id) + "')\">Log</button> " +
            '<button class="button" onclick="jobstream(\'' + esc(j.id) +
            "')\">Live</button> " +
            '<button class="button danger" onclick="jobkill(\'' + esc(j.id) +
            "')\">Kill</button></td></tr>";
        }
        setView(h + "</table></div>" +
          '<div class="card"><h3>Job log</h3><pre id="jl">select a job</pre></div>');
      });
    },

    approvals: function () {
      return api("GET", "/api/v3/approvals").then(function (r) {
        var list = r.d.approvals || [];
        setTitle("Approvals");
        if (!list.length) {
          setView('<div class="card">No pending approvals.</div>');
          return;
        }
        var h = '<div class="card"><h3>Pending gates</h3><table>' +
          "<tr><th>ID</th><th>Job</th><th>Task</th><th>Tier</th><th>Message</th><th></th></tr>";
        for (var i = 0; i < list.length; i++) {
          var a = list[i];
          var confirmBox = a.tier === 3
            ? '<input id="c-' + esc(a.id) + '" placeholder="type CONFIRM" size="12">'
            : "";
          h += "<tr><td>" + esc(a.id) + "</td><td>" + esc(a.job_id) +
            "</td><td>" + esc(a.task) + "</td><td>T" + a.tier + "</td><td>" +
            esc(a.message || "") + "</td><td>" + confirmBox +
            '<button class="button" onclick="decide(\'' + esc(a.id) +
            "',true)\">Approve</button> " +
            '<button class="button danger" onclick="decide(\'' + esc(a.id) +
            "',false)\">Deny</button></td></tr>";
        }
        setView(h + "</table></div>");
      });
    },

    findings: function () {
      if (!SID) {
        setView('<div class="card">Open a session first (Sessions tab).</div>');
        return Promise.resolve();
      }
      return api("GET", "/api/v3/sessions/" + SID + "/findings").then(function (r) {
        var list = r.d.findings || [];
        setTitle("Findings @ " + SID);
        var h =
          '<div class="card"><div class="row">' +
          '<button class="button" onclick="doverify()">Re-verify all</button>' +
          '<button class="button" onclick="doenrich()">Auto-enrich intel</button>' +
          '<button class="button" onclick="doloot()">Loot triage</button>' +
          '<button class="button warn" onclick="autoexploit(\'prove\')">Auto-exploit (prove)</button>' +
          "</div><table>" +
          "<tr><th>Severity</th><th>Title</th><th>Source</th><th>Tags</th><th>Actions</th></tr>";
        for (var i = 0; i < list.length; i++) {
          var f = list[i];
          h += "<tr>" + sevCell(f) + "<td>" + esc(f.title) + "</td><td>" +
            esc(f.source) + "</td><td>" + esc((f.tags || []).join(", ")) +
            '</td><td><button class="button" onclick="fvalidate(\'' +
            esc(f.id) + "')\">Validate</button> " +
            '<button class="button danger" onclick="fexploit(\'' +
            esc(f.id) + "')\">Exploit</button></td></tr>";
        }
        setView(h + "</table></div>" +
          '<div class="card"><h3>Action output</h3><pre id="ao">—</pre></div>');
      });
    },
    graph: function () {
      if (!SID) {
        setView('<div class="card">Open a session first.</div>');
        return Promise.resolve();
      }
      return api("GET", "/api/v3/sessions/" + SID + "/kill-chain").then(function (r) {
        var stages = (r.d && r.d.stages) || {};
        setTitle("Attack Graph");
        var h = '<div class="card"><h3>Kill-chain coverage</h3><table>' +
          "<tr><th>Stage</th><th>Findings</th></tr>";
        for (var name in stages) {
          if (!Object.prototype.hasOwnProperty.call(stages, name)) continue;
          var items = stages[name] || [];
          if (!items.length) continue;
          var width = Math.min(100, items.length * 20);
          h += "<tr><td>" + esc(name) +
            '</td><td><div style="background:#2a3f5f;border-radius:4px">' +
            '<div style="background:#00d4ff;height:10px;border-radius:4px;width:' +
            width + '%"></div></div> ' + items.length + "</td></tr>";
        }
        setView(h + "</table></div>");
      });
    },

    reports: function () {
      if (!SID) {
        setView('<div class="card">Open a session first.</div>');
        return Promise.resolve();
      }
      var rep, rem;
      return api("GET", "/api/v3/sessions/" + SID + "/reports").then(function (r) {
        rep = r.d;
        return api("GET", "/api/v3/sessions/" + SID + "/remediation");
      }).then(function (r2) {
        rem = r2.d;
        setTitle("Reports");
        var files = rep.reports || [];
        var h = '<div class="card"><div class="row">' +
          '<button class="button" onclick="mkpdf()">Build executive PDF</button>' +
          '<button class="button" onclick="dorisk()">Risk analysis (v2)</button>' +
          "</div><table><tr><th>File</th><th>Size</th><th></th></tr>";
        for (var i = 0; i < files.length; i++) {
          var dl = "/api/v3/sessions/" + SID + "/reports/" +
            encodeURIComponent(files[i].name) + "?token=" + T;
          h += "<tr><td>" + esc(files[i].name) + "</td><td>" + files[i].size +
            '</td><td><a class="button" href="' + dl + '">Download</a></td></tr>';
        }
        h += "</table></div>" +
          '<div class="card"><h3>Remediation</h3><pre>' +
          esc(JSON.stringify(rem, null, 1)) + "</pre></div>" +
          '<div class="card"><h3>Risk output</h3><pre id="ro">—</pre></div>';
        setView(h);
      });
    },

    c2: function () {
      var st;
      return api("GET", "/api/v3/c2/listener/status").then(function (r) {
        st = r.d || {};
        return api("GET", "/api/v3/c2/overview");
      }).then(function (r) {
        var list = r.d.agents || [];
        setTitle("C2");
        var h = '<div class="card"><h3>Listener: ' +
          (st.running ? '<b class="good">RUNNING ' + esc(String(st.host)) +
             ":" + esc(String(st.port)) + "</b>" : '<b class="bad">stopped</b>') +
          "</h3>" +
          '<div class="row"><input id="ch" value="127.0.0.1" size="14">' +
          '<input id="cp" value="4443" size="6">' +
          '<button class="button" onclick="c2l(true)">Start</button>' +
          '<button class="button" onclick="c2l(false)">Stop</button></div>' +
          "<p>Agents beacon in over JSON-lines TCP using the controller " +
          "token (shown at start). Channels dns/icmp/websocket/p2p are " +
          "not implemented.</p></div>";
        h += '<div class="card"><h3>Agents (' + list.length + ")</h3><table>" +
          "<tr><th>ID</th><th>Host</th><th>User</th><th>Status</th><th>Pending</th></tr>";
        for (var i = 0; i < list.length; i++) {
          var a = list[i];
          var label = a.agent_id || a.id || JSON.stringify(a).slice(0, 40);
          var pend = a.pending_commands === undefined ? "" : a.pending_commands;
          h += "<tr><td>" + esc(label) + "</td><td>" + esc(a.hostname || "") +
            "</td><td>" + esc(a.username || "") + "</td><td>" +
            esc(a.status || "") + "</td><td>" + esc(String(pend)) + "</td></tr>";
        }
        h += "</table></div>" +
          '<div class="card"><h3>Queue task</h3><div class="row">' +
          '<input id="ca" placeholder="agent id">' +
          '<input id="cc" placeholder="command">' +
          '<button class="button" onclick="c2t()">Queue</button>' +
          '</div><pre id="co"></pre></div>';
        setView(h);
      });
    },

    v2: function () {
      setTitle("V2 Toolkit");
      var tk, cov;
      return api("GET", "/api/v3/v2/toolkit").then(function (r) {
        tk = r.d;
        return api("GET", "/api/v3/v2/coverage");
      }).then(function (r2) {
        cov = r2.d;
        var h = '<div class="card"><h3>Frameworks (' + tk.classes_ok +
          ' classes wired)</h3><table>' +
          "<tr><th>Module</th><th>Classes / methods</th></tr>";
        for (var i = 0; i < tk.modules.length; i++) {
          var m = tk.modules[i];
          var cls = [];
          for (var j = 0; j < m.classes.length; j++) {
            cls.push(m.classes[j].name + " (" +
              (m.classes[j].methods || []).length + ")");
          }
          h += "<tr><td>" + esc(m.module) + "</td><td>" +
            esc(cls.join(", ")) + "</td></tr>";
        }
        h += "</table></div>" +
          '<div class="card"><h3>Tool coverage (' + cov.installed + "/" +
          cov.count + ' installed)</h3><table>' +
          "<tr><th>Tool</th><th>Task</th><th>Installed</th></tr>";
        var tools = cov.tools || [];
        for (var k = 0; k < tools.length; k++) {
          h += "<tr><td>" + esc(tools[k].tool) + "</td><td>" +
            esc(tools[k].task) + "</td><td>" +
            (tools[k].installed ? "yes" : "NO") + "</td></tr>";
        }
        h += "</table></div>" +
          '<div class="card"><h3>Payload generator (Tier-3)</h3>' +
          '<div class="row"><select id="pk">' +
          '<option value="powershell">powershell</option>' +
          '<option value="python">python</option></select>' +
          '<input id="pc" placeholder="c2 server">' +
          '<input id="px" placeholder=\'type CONFIRM\'>' +
          '<button class="button danger" onclick="v2pay()">Generate</button>' +
          '</div><pre id="po"></pre></div>';
        setView(h);
      });
    },

    surface: function () {
      if (!SID) {
        setView('<div class="card">Open a session first.</div>');
        return Promise.resolve();
      }
      return api("GET", "/api/v3/sessions/" + SID + "/surface").then(function (r) {
        var list = r.d.candidates || [];
        setTitle("Attack Surface");
        var h = '<div class="card"><div class="row">' +
          '<button class="button" onclick="surfvalidate()">Validate all (Tier-2)</button>' +
          "</div><table>" +
          "<tr><th>Type</th><th>URL</th><th>Detail</th><th>Validator</th><th></th></tr>";
        for (var i = 0; i < list.length; i++) {
          var c = list[i];
          h += "<tr><td>" + esc(c.type) + "</td><td>" + esc(c.url) + "</td><td>" +
            esc(c.detail) + "</td><td>" + esc(c.validator) + "</td>" +
            '<td><button class="button" onclick="surf1(' + i + ')">Test</button></td></tr>';
        }
        window.__surf = list;
        setView(h + "</table></div>" +
          '<div class="card"><h3>Validation output</h3><pre id="so">—</pre></div>');
      });
    },

    recon: function () {
      if (!SID) {
        setView('<div class="card">Open a session first.</div>');
        return Promise.resolve();
      }
      var mods = ["wayback", "dorkpack", "subpermute", "subvalidate",
        "cohosted", "asn", "s3", "github", "jsminer", "waf", "headers",
        "methods", "robots", "subbrute", "direnum", "portfp", "crawler"];
      setTitle("Recon+");
      var h = '<div class="card"><h3>Boss workflow modules</h3>' +
        '<div class="row">' +
        mods.map(function (m) {
          return '<button class="button" onclick="reconrun(\'' + m + "')\">" + m + "</button>";
        }).join("") +
        "</div><pre id=\"rx\">pick a module</pre></div>";
      setView(h);
      return Promise.resolve();
    },

    attacks: function () {
      return api("GET", "/api/v3/attacks").then(function (r) {
        var list = r.d.attacks || [];
        window.__atklist = list;
        setTitle("Attack Runner", "P1 / P2 / P3 · tier-gated");
        var opts = "<option value=\"\">— select attack —</option>";
        for (var i = 0; i < list.length; i++) {
          var a = list[i];
          opts += "<option value=\"" + esc(a.id) + "\">" + esc(a.phase) +
            " T" + esc(a.tier) + " · " + esc(a.id) + "</option>";
        }
        var h = "<div class=\"card\"><h3>Attack modules (" +
          list.length + ")</h3>" +
          '<div class="row"><select id="at-sel" onchange="atSelChange()">' + opts + "</select>" +
          '<input id="at-target" placeholder="target / domain (in scope)">' +
          '<input id="at-confirm" placeholder="confirm word" size="10">' +
          '<button class="button" onclick="atrun(\'plan\')">Plan</button>' +
          '<button class="button danger" onclick="atrun(\'exec\')">' +
          "Execute</button></div>" +
          "<table><tr><th>Phase</th><th>Tier</th><th>ID</th>" +
          "<th>Module</th></tr>";
        for (var j = 0; j < list.length; j++) {
          var m = list[j];
          h += "<tr><td>" + esc(m.phase) + "</td><td>" + esc(m.tier) +
            "</td><td>" + esc(m.id) + "</td><td>" + esc(m.title) +
            '<div style="opacity:.7;font-size:11px">' + esc(m.summary) +
            "</div></td></tr>";
        }
        h += "</table></div>" +
          '<div class="card"><h3>Attack output</h3>' +
          '<pre id="ato">—</pre></div>';
        setView(h);
        if (SID) {
          api("GET", "/api/v3/sessions/" + SID).then(function (sr) {
            var body = sr.d.session || sr.d;
            var t = (body.meta && body.meta.target) || body.target || "";
            var box = document.getElementById("at-target");
            if (box && t && !box.value) box.value = t;
          });
        }
      });
    },
    chains: function () {
      return api("GET", "/api/v3/chains").then(function (r) {
        var list = r.d.chains || [];
        setTitle("Attack Chains");
        var h = '<div class="card"><p style="font-size:12px;color:#889">' +
          "Each chain executes step-by-step and STOPS at the first failed " +
          "step — no blind follow-ups. Tier-3: type CONFIRM to run.</p>" +
          '<div class="row"><input id="chspec" placeholder=\'spec JSON e.g. {"host":"1.2.3.4","port":1433,"service":"mssql"}\' size="50">' +
          '<input id="chconf" placeholder="type CONFIRM" size="12"></div>' +
          "<table><tr><th>Chain</th><th>Vector</th><th>OWASP</th><th>Steps</th><th></th></tr>";
        for (var i = 0; i < list.length; i++) {
          var ch = list[i];
          h += "<tr><td>" + esc(ch.title) + "</td><td>" + esc(ch.vector) +
            "</td><td>" + esc(ch.owasp) + "</td><td>" +
            esc((ch.steps || []).join(" → ")) + "</td>" +
            '<td><button class="button danger" onclick="chainrun(\'' +
            esc(ch.id) + "')\">Run</button></td></tr>";
        }
        window.__chains = list;
        setView(h + "</table></div>" +
          '<div class="card"><h3>Transcript</h3><pre id="ct">—</pre></div>');
      });
    },

    opsec: function () {
      var o, px;
      return api("GET", "/api/v3/opsec").then(function (r) {
        o = r.d;
        return api("GET", "/api/v3/opsec/proxy");
      }).then(function (r2) {
        px = r2.d;
        setTitle("OPSEC");
        var h = '<div class="card"><h3>Stealth engine</h3><table>' +
          "<tr><th>Rate limit</th><td>" + esc(o.rate_limit) + " req/s</td></tr>" +
          "<tr><th>Profiles</th><td>" + esc((o.profiles || []).join(", ")) +
          "</td></tr></table>" +
          '<div class="row"><select id="op">' +
          "<option>quiet</option><option>normal</option><option>loud</option>" +
          '</select><button class="button warn" onclick="opswitch()">Apply profile</button>' +
          "</div><pre id=\"oo\"></pre></div>" +
          '<div class="card"><h3>Egress</h3><table>' +
          "<tr><th>Active</th><td>" + esc(px.active || "DIRECT (no proxy)") + "</td></tr>" +
          "<tr><th>Configured</th><td>" + esc((px.proxies || []).join(", ") || "none") + "</td></tr>" +
          "<tr><th>Tor</th><td>" + (px.tor_configured ? "configured" : "off") + "</td></tr>" +
          "</table>" +
          '<div class="row"><button class="button" onclick="tornew()">Tor NEWNYM</button>' +
          '<button class="button" onclick="opaudit()">Run OPSEC audit</button>' +
          '<button class="button" onclick="egress()">Verify egress IP</button></div>' +
          "<pre id=\"op2\"></pre></div>" +
          '<div class="card"><h3>DNS-over-HTTPS</h3><div class="row">' +
          '<input id="dh" placeholder="hostname">' +
          '<button class="button" onclick="doh()">Resolve</button></div>' +
          "<pre id=\"do\"></pre></div>" +
          '<div class="card"><h3>Track-cover scripts</h3>' +
          '<div class="row"><button class="button" onclick="tcgen()">Generate for open session</button></div>' +
          "<pre id=\"tc\"></pre></div>";
        setView(h);
      });
    },

    payloads: function () {
      var repos, tamp, stats;
      return api("GET", "/api/v3/payload-repos").then(function (r) {
        repos = r.d.repos || [];
        return api("GET", "/api/v3/tampers");
      }).then(function (r2) {
        tamp = r2.d.tampers || [];
        return api("GET", "/api/v3/payloaddb/stats");
      }).then(function (r3) {
        stats = r3.d;
        setTitle("Payloads");
        var h = '<div class="card"><h3>Local payload DB (' +
          stats.total_files + ' files, ' + stats.total_lines + ' lines)</h3>' +
          '<div class="row"><select id="pc">' +
          stats.categories.map(function (c) {
            return '<option value="' + esc(c.category) + '">' + esc(c.category) +
              " (" + c.lines + ")</option>";
          }).join("") +
          '</select><button class="button" onclick="pdbpreview()">Preview</button>' +
          '<button class="button" onclick="pdbexport()">Export wordlist</button>' +
          '<button class="button warn" onclick="pdbfuzz()">Fuzz open session</button></div>' +
          "<pre id=\"po2\">—</pre></div>" +
          '<div class="card"><h3>Brute-force lists</h3><div class="row">' +
          '<button class="button" onclick="brutelists()">Show lists</button></div>' +
          "<pre id=\"bl\"></pre></div>" +
          '<div class="card"><h3>GitHub repos (clone: sudo tools/fetch_payloads.sh)</h3><table>' +
          "<tr><th>Dir</th><th>Covers</th><th>Cloned</th></tr>";
        for (var i = 0; i < repos.length; i++) {
          h += "<tr><td>" + esc(repos[i].dir) + "</td><td>" +
            esc(repos[i].covers) + "</td><td>" +
            (repos[i].cloned ? "yes (" + repos[i].files + " files)" : "no") +
            "</td></tr>";
        }
        h += "</table></div>" +
          '<div class="card"><h3>Tamper kit (built-in encodings)</h3><table>' +
          "<tr><th>Name</th><th>Use</th></tr>";
        for (var j = 0; j < tamp.length; j++) {
          h += "<tr><td>" + esc(tamp[j].name) + "</td><td>" +
            esc(tamp[j].use) + "</td></tr>";
        }
        setView(h + "</table></div>");
      });
    },

    preflight: function () {
      return api("GET", "/api/v3/preflight").then(function (r) {
        var d = r.d;
        setTitle("Preflight");
        var h = '<div class="card"><h3>Ready: ' + (d.ready ? "YES" : "NO") +
          "</h3><p>Setup: <code>" + esc(d.setup_hint) + "</code></p>" +
          "<table><tr><th>Tool</th><th>Installed</th><th>Fix</th></tr>";
        var tools = d.tools || [];
        for (var i = 0; i < tools.length; i++) {
          h += "<tr><td>" + esc(tools[i].tool) + "</td><td>" +
            (tools[i].installed ? "yes" : "NO") + "</td><td>" +
            esc(tools[i].fix || "") + "</td></tr>";
        }
        h += "</table><table><tr><th>Python</th><th>Installed</th><th>Fix</th></tr>";
        var py = d.python || [];
        for (var j = 0; j < py.length; j++) {
          h += "<tr><td>" + esc(py[j].package) + "</td><td>" +
            (py[j].installed ? "yes" : "NO") + "</td><td>" +
            esc(py[j].fix || "") + "</td></tr>";
        }
        setView(h + "</table></div>");
      });
    },

    settings: function () {
      setTitle("Settings — API Keys");
      return api("GET", "/api/v3/settings/keys").then(function (r) {
        var d = r.d || {};
        var h = '<div class="card"><h3>API Keys</h3>' +
          "<p>Resolution order: environment variable &rarr; <code>" +
          esc(d.file || "config/api_keys.yaml") +
          "</code> (0600, gitignored) &rarr; ardf.yaml. Values are shown " +
          "masked only &mdash; the server never sends them back in full." +
          "</p>" +
          '<table><tr><th>Key</th><th>Env var</th><th>Status</th>' +
          "<th>Source</th><th>Value</th><th>Actions</th></tr>";
        var keys = d.keys || [];
        for (var i = 0; i < keys.length; i++) {
          var k = keys[i];
          h += "<tr><td>" + esc(k.name) + "</td><td><code>" +
            esc(k.env_var) + "</code></td><td>" +
            (k.configured ? '<b class="good">set</b>' :
              '<b class="bad">unset</b>') + "</td><td>" +
            esc(k.source) + "</td><td><code>" + esc(k.masked || "—") +
            '</code></td><td>' +
            '<input id="ak-' + esc(k.name) +
            '" type="password" placeholder="new value" size="16"> ' +
            '<button class="button" onclick="_saveKey(\'' + esc(k.name) +
            '\')">Save</button> ' +
            (k.source === "file" ?
              '<button class="button" onclick="_delKey(\'' + esc(k.name) +
              '\')">Del</button>' : "") +
            "</td></tr>";
        }
        h += "</table><p>Saving writes to the keys file (mode 0600). " +
          "Environment variables always take precedence over stored " +
          "values. Recon modules pick these up automatically.</p></div>";
        setView(h);
      });
    },
  };

  // ── module grid ───────────────────────────────────────────
  function _modMatch(a) {
    var f = window.__modfilter || { phase: "ALL", q: "" };
    if (f.phase && f.phase !== "ALL") {
      if (f.phase.charAt(0) === "T") {
        if (String(a.tier) !== f.phase.charAt(1)) return false;
      } else if (a.phase !== f.phase) {
        return false;
      }
    }
    var q = (f.q || "").toLowerCase().trim();
    if (!q) return true;
    return (a.id + " " + a.title + " " + a.summary + " " + a.phase)
      .toLowerCase().indexOf(q) >= 0;
  }

  function modRender() {
    var grid = document.getElementById("modgrid");
    if (!grid) return;
    var list = (window.__modlist || []).filter(_modMatch);
    var sel = window.__modsel;
    var h = "";
    for (var i = 0; i < list.length; i++) {
      var a = list[i];
      var tier = "t" + a.tier;
      h += '<div class="module-card' +
        (sel && sel.id === a.id ? " selected" : "") +
        '" onclick="modPick(\'' + esc(a.id) + "')\">" +
        '<div class="mc-top"><span class="mc-id">' + esc(a.id) + "</span>" +
        '<span class="tier ' + tier + '">' + esc(a.phase) + " · T" + a.tier +
        "</span></div>" +
        '<div class="mc-title">' + esc(a.title) + "</div>" +
        '<div class="mc-sum">' + esc(a.summary) + "</div></div>";
    }
    grid.innerHTML = h || '<div class="event-empty">No modules match that filter.</div>';
    var c = document.getElementById("mod-count");
    if (c) c.textContent = list.length + " / " + (window.__modlist || []).length + " modules";
    var detail = document.getElementById("moddetail");
    if (!detail) return;
    if (!sel) {
      detail.innerHTML = '<p class="muted">Select a card to load its runner. ' +
        "Tier-1 is read-only, Tier-2 is an active probe, Tier-3 needs the typed word.</p>";
      return;
    }
    var need = sel.tier >= 3 ? "CONFIRM" : sel.tier === 2 ? "APPROVE" : "not required";
    detail.innerHTML = '<div class="selected-id">' + esc(sel.id) + "</div>" +
      '<div class="mc-title" style="font-size:14px;margin-top:3px">' +
      esc(sel.title) + "</div>" +
      '<p class="runner-meta" style="margin:7px 0 10px">' + esc(sel.summary) + "</p>" +
      '<div class="pill-row"><span class="pill"><b>' + esc(sel.phase) +
      "</b> phase</span><span class=\"pill\"><b>T" + sel.tier +
      "</b> tier</span><span class=\"pill\">confirm <b>" + esc(need) +
      "</b></span></div>";
    var box = document.getElementById("mod-confirm");
    if (box) box.placeholder = sel.tier >= 3 ? "CONFIRM" :
      sel.tier === 2 ? "APPROVE or CONFIRM" : "not required";
  }

  function modFilter(phase) {
    window.__modfilter = window.__modfilter || { phase: "ALL", q: "" };
    window.__modfilter.phase = phase;
    var bs = document.querySelectorAll("#mod-phases .button");
    for (var i = 0; i < bs.length; i++) {
      var on = bs[i].getAttribute("data-phase") === phase;
      bs[i].className = "button" + (on ? " active" : "");
    }
    modRender();
  }

  function modSearch() {
    window.__modfilter = window.__modfilter || { phase: "ALL", q: "" };
    var q = document.getElementById("modq");
    window.__modfilter.q = q ? q.value : "";
    modRender();
  }

  function modPick(id) {
    var list = window.__modlist || [];
    window.__modsel = null;
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) { window.__modsel = list[i]; break; }
    }
    modRender();
  }

  function modRun(mode) {
    var a = window.__modsel;
    if (!a) { toast("select a module first", "warn"); return; }
    if (!SID) { toast("open a session first", "warn"); return; }
    var target = (document.getElementById("mod-target") || {}).value || "";
    var confirm = (document.getElementById("mod-confirm") || {}).value || "";
    var word = confirm.trim().toUpperCase();
    if (mode === "exec") {
      if (a.tier >= 3 && word !== "CONFIRM") {
        toast("Tier-3 requires the typed word CONFIRM", "warn");
        return;
      }
      if (a.tier === 2 && word !== "APPROVE" && word !== "CONFIRM") {
        toast("Tier-2 requires APPROVE (or CONFIRM)", "warn");
        return;
      }
    }
    var out = document.getElementById("mod-out");
    if (out) out.textContent = "running " + a.id + " (" + mode + ")…";
    api("POST", "/api/v3/attacks/run", {
      session_id: SID, attack: a.id, mode: mode, confirm_text: confirm,
      spec: { target: target, mode: mode, confirm_text: confirm },
    }).then(function (r) {
      var res = r.d && r.d.result ? r.d.result : r.d;
      var txt = typeof res === "string" ? res : JSON.stringify(res, null, 1);
      if (out) out.textContent = txt;
      var lines = String(txt).split("\n");
      for (var i = 0; i < lines.length; i++) _termLines.push("[mod] " + lines[i]);
      if (r.status !== 200) toast("module returned " + r.status, "err");
    });
  }

  function atSelChange() {
    var sel = document.getElementById("at-sel");
    var box = document.getElementById("at-confirm");
    if (!sel || !box) return;
    var a = null;
    var list = window.__atklist || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === sel.value) { a = list[i]; break; }
    }
    box.placeholder = !a ? "confirm word" : a.tier >= 3 ? "CONFIRM" :
      a.tier === 2 ? "APPROVE" : "not required";
  }

  function ovQuick() {
    var t = (document.getElementById("ov-target") || {}).value || "";
    var p = (document.getElementById("ov-pb") || {}).value || "passive";
    api("POST", "/api/v3/jobs", { playbook: p, target: t }).then(function (r) {
      if (r.status === 201) {
        toast("job " + r.d.id + " queued");
        go("jobs");
      } else {
        toast("ERR: " + ((r.d && r.d.error) || r.status), "err");
      }
    });
  }

  // ── command palette ───────────────────────────────────────
  var _palItems = [];
  var _palIdx = 0;

  function _paletteSource() {
    var out = [];
    for (var i = 0; i < TABS.length; i++) {
      out.push({ label: TABS[i][1], group: TABS[i][2], icon: TABS[i][3],
                 run: (function (id) { return function () { go(id); }; })(TABS[i][0]) });
    }
    out.push({ label: "Run preflight", group: "ACTION", icon: "✚",
               run: function () { go("preflight"); } });
    out.push({ label: "New session", group: "ACTION", icon: "▣",
               run: function () { go("sessions"); } });
    out.push({ label: "Open module grid", group: "ACTION", icon: "▦",
               run: function () { go("modules"); } });
    out.push({ label: "Disconnect", group: "ACTION", icon: "⏻",
               run: logout });
    return out;
  }

  function _palRender() {
    var box = document.getElementById("palette-list");
    if (!box) return;
    var q = (document.getElementById("palette-input") || {}).value || "";
    q = q.toLowerCase().trim();
    _palItems = _paletteSource().filter(function (x) {
      return !q || (x.label + " " + x.group).toLowerCase().indexOf(q) >= 0;
    }).slice(0, 24);
    if (_palIdx >= _palItems.length) _palIdx = 0;
    var h = "";
    for (var i = 0; i < _palItems.length; i++) {
      var it = _palItems[i];
      h += '<div class="palette-item' + (i === _palIdx ? " active" : "") +
        '" onclick="paletteRun(' + i + ')">' +
        '<span class="pi">' + esc(it.icon) + "</span><span>" +
        esc(it.label) + '</span><span class="pg">' + esc(it.group) +
        "</span></div>";
    }
    box.innerHTML = h || '<div class="palette-empty">No matching command.</div>';
  }

  function openPalette() {
    if (!T) return;
    var p = document.getElementById("palette");
    if (!p) return;
    p.classList.remove("hidden");
    var inp = document.getElementById("palette-input");
    if (inp) { inp.value = ""; try { inp.focus(); } catch (e) {} }
    _palIdx = 0;
    _palRender();
  }

  function paletteFilter() {
    _palIdx = 0;
    _palRender();
  }

  function closePalette() {
    var p = document.getElementById("palette");
    if (p) p.classList.add("hidden");
  }

  function paletteRun(i) {
    var it = _palItems[i];
    if (!it) return;
    closePalette();
    it.run();
  }

  function _palKey(e) {
    var p = document.getElementById("palette");
    if (!p || p.classList.contains("hidden")) return;
    if (e.key === "Escape") { closePalette(); e.preventDefault(); }
    else if (e.key === "ArrowDown") { _palIdx = Math.min(_palIdx + 1, _palItems.length - 1); _palRender(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { _palIdx = Math.max(_palIdx - 1, 0); _palRender(); e.preventDefault(); }
    else if (e.key === "Enter") { paletteRun(_palIdx); e.preventDefault(); }
  }

  document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette();
      return;
    }
    _palKey(e);
  });

  function tickClock() {
    var el = document.getElementById("clock");
    if (el) el.textContent = new Date().toISOString().slice(11, 19);
  }
  tickClock();
  window.setInterval(tickClock, 1000);

  function scopeadd() {
    api("POST", "/api/v3/scope/targets",
        { entry: document.getElementById("sadd").value }).then(function (r) {
      toast(r.d.error || "target added");
      if (!r.d.error) _applyScope(r.d);
      go("dash");
    });
  }
  function scopedel(entry) {
    if (!confirm("Remove " + entry + " from scope?")) return;
    api("DELETE", "/api/v3/scope/targets", { entry: entry }).then(function (r) {
      toast(r.d.error || "removed");
      if (!r.d.error) _applyScope(r.d);
      go("dash");
    });
  }
  function scopetoggle() {
    api("GET", "/api/v3/scope").then(function (r) {
      return api("POST", "/api/v3/scope/enabled",
                 { enabled: !r.d.enabled });
    }).then(function (r2) {
      _applyScope(r2.d);
      go("dash");
    });
  }
  function quick() {
    var t = document.getElementById("qtarget").value;
    var p = document.getElementById("qpb").value;
    api("POST", "/api/v3/jobs", { playbook: p, target: t }).then(function (r) {
      if (r.status === 201) {
        toast("job " + r.d.id + " queued");
        go("jobs");
      } else {
        toast("ERR: " + ((r.d && r.d.error) || r.status), "err");
      }
    });
  }

  function newsess() {
    var t = document.getElementById("nt").value;
    var m = document.getElementById("nm").value;
    api("POST", "/api/v3/sessions", { target: t, mode: m }).then(function (r) {
      if (r.status === 201) {
        toast("session " + r.d.session_id + " created");
        go("sessions");
      } else {
        toast("ERR: " + ((r.d && r.d.error) || r.status), "err");
      }
    });
  }

  function pick(id) { SID = id; go("findings"); }
  function delsess(id) {
    var c = prompt("Delete session " + id + "? Type DELETE to confirm:");
    if (c !== "DELETE") return;
    api("DELETE", "/api/v3/sessions/" + id, { confirm_text: "DELETE" }).then(function (r) {
      alert(r.d.deleted ? "deleted" : "ERR: " + (r.d.error || r.status));
      if (SID === id) SID = "";
      go("sessions");
    });
  }
  function fact(fid) {
    api("GET", "/api/v3/sessions/" + SID + "/findings/actions?finding_id=" +
        encodeURIComponent(fid)).then(function (r) {
      var acts = (r.d.actions || []).map(function (a) {
        return a.action + " (T" + a.tier + "): " + a.label;
      }).join("\n");
      document.getElementById("ao").textContent = acts || JSON.stringify(r.d);
    });
  }
  function fvalidate(fid) {
    document.getElementById("ao").textContent = "validating…";
    api("POST", "/api/v3/sessions/" + SID + "/actions",
        { action: "validate", finding_id: fid }).then(function (r) {
      document.getElementById("ao").textContent = JSON.stringify(r.d, null, 1).slice(0, 2000);
    });
  }
  function fexploit(fid) {
    var c = prompt("Tier-3 exploit proof. Type CONFIRM to proceed:");
    if (c !== "CONFIRM") return;
    var el = document.getElementById("ao");
    el.textContent = "exploiting (safe proof subset)…\n";
    var t0 = Date.now();
    api("POST", "/api/v3/sessions/" + SID + "/actions",
        { action: "exploit", finding_id: fid, confirm_text: c }).then(function (r) {
      var d = r.d || {};
      var out = typeof d === "string" ? d : JSON.stringify(d, null, 1);
      el.textContent += "\n--- exploit result (" +
        Math.round((Date.now() - t0) / 1000) + "s) ---\n" + out;

      var lines = out.split("\n");
      for (var i = 0; i < lines.length; i++) {
        _termLines.push("[exp] " + lines[i]);
      }
      var tel = document.getElementById("termout");
      if (tel && CUR === "term") tel.textContent = _termLines.join("\n");
      if (tel) tel.scrollTop = tel.scrollHeight;

      if (r.d.job_id) jobstream(r.d.job_id);
    });
  }
  function egress() {
    api("GET", "/api/v3/opsec/egress-verify").then(function (r) {
      document.getElementById("op2").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function atrun(mode) {
    var sel = document.getElementById("at-sel");
    var id = sel ? sel.value : "";
    if (!id || !SID) {
      var el = document.getElementById("ato");
      if (el) {
        el.textContent = !SID ? "open a session first"
          : "select an attack id";
      }
      return;
    }
    var target = (document.getElementById("at-target") || {}).value || "";
    var ctext = (document.getElementById("at-confirm") || {}).value || "";
    var a = null;
    var list = window.__atklist || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) { a = list[i]; break; }
    }
    var word = ctext.trim().toUpperCase();
    if (mode === "exec" && a) {
      if (a.tier >= 3 && word !== "CONFIRM") {
        toast("Tier-3 requires CONFIRM", "warn");
        return;
      }
      if (a.tier === 2 && word !== "APPROVE" && word !== "CONFIRM") {
        toast("Tier-2 requires APPROVE (or CONFIRM)", "warn");
        return;
      }
    }
    var outEl = document.getElementById("ato");
    if (outEl) outEl.textContent = "running " + id + " (" + mode + ")…";
    api("POST", "/api/v3/attacks/run",
        { session_id: SID, attack: id, mode: mode,
          confirm_text: ctext,
          spec: { target: target, mode: mode, confirm_text: ctext,
                  login_url: target } })
      .then(function (r) {
        var out = (r.d && r.d.result) || r.d;
        var txt = typeof out === "string"
          ? out : JSON.stringify(out, null, 1);
        if (outEl) outEl.textContent = txt;
        var lines = txt.split("\n");
        for (var j = 0; j < lines.length; j++) {
          _termLines.push("[atk] " + lines[j]);
        }
        var tel = document.getElementById("termout");
        if (tel && CUR === "term") tel.textContent = _termLines.join("\n");
        if (r.status !== 200) toast("attack returned " + r.status, "err");
      });
  }

  function joblog(id) {
    stopStream();
    api("GET", "/api/v3/jobs/" + id).then(function (r) {
      document.getElementById("jl").textContent =
        (r.d.log_tail || []).join("\n") + "\n--- tasks ---\n" +
        JSON.stringify(r.d.tasks || [], null, 1);
    });
  }
  var _es = null;
  function stopStream() {
    if (_es) { try { _es.close(); } catch (e) {} _es = null; }
  }
  function jobstream(id) {
    stopStream();
    var el = document.getElementById("jl");
    el.textContent = "streaming " + id + "…\n";
    _es = new EventSource("/api/v3/jobs/" + id + "/stream?token=" + T);
    _es.onmessage = function (ev) {
      try {
        var d = JSON.parse(ev.data);
        if (d.line) el.textContent += d.line + "\n";
        if (d.status) {
          el.textContent += "--- " + d.status + " ---\n";
          stopStream();
        }
        el.scrollTop = el.scrollHeight;
      } catch (e) {}
    };
    _es.onerror = function () {
      el.textContent += "[stream closed]\n";
      stopStream();
    };
  }
  function jobkill(id) {
    if (!confirm("Kill job " + id + "?")) return;
    stopStream();
    api("DELETE", "/api/v3/jobs/" + id, {}).then(function (r) {
      toast("job " + (r.d.status || r.d.error));
      go("jobs");
    });
  }

  function decide(id, ok) {
    var b = { approved: ok };
    if (ok) {
      var el = document.getElementById("c-" + id);
      if (el) b.confirm_text = el.value;
    }
    api("POST", "/api/v3/approvals/" + id, b).then(function (r) {
      if (r.d.error) alert(r.d.error);
      go("approvals");
    });
  }

  function actionOut(promise, refresh) {
    promise.then(function (r) {
      document.getElementById("ao").textContent = JSON.stringify(r.d, null, 1);
      if (refresh) views.findings();
    });
  }

  function doverify() {
    actionOut(api("POST", "/api/v3/sessions/" + SID + "/verify"), true);
  }
  function doenrich() {
    actionOut(api("POST", "/api/v3/sessions/" + SID + "/enrich"), false);
  }
  function doloot() {
    api("GET", "/api/v3/sessions/" + SID + "/loot").then(function (r) {
      document.getElementById("ao").textContent =
        JSON.stringify(r.d, null, 1).slice(0, 3000);
    });
  }
  var _axTimer = null;
  function autoexploit(mode) {
    api("POST", "/api/v3/sessions/" + SID + "/autoexploit",
        { mode: mode }).then(function (r) {
      if (r.d.error) {
        document.getElementById("ao").textContent = r.d.error;
        return;
      }
      var id = r.d.id;
      document.getElementById("ao").textContent =
        "auto-exploit " + id + " running…";
      if (_axTimer) clearInterval(_axTimer);
      _axTimer = setInterval(function () {
        api("GET", "/api/v3/autoexploit/" + id).then(function (r2) {
          var d = r2.d;
          document.getElementById("ao").textContent =
            JSON.stringify(d.result || d, null, 1).slice(0, 3000);
          if (d.status === "complete" || d.status === "failed" ||
              d.status === "killed") {
            clearInterval(_axTimer);
            toast("auto-exploit " + d.status);
          }
        });
      }, 3000);
    });
  }
  function mkpdf() {
    api("POST", "/api/v3/sessions/" + SID + "/pdf").then(function (r) {
      alert(r.d.file ? "PDF: " + r.d.file : "ERR: " + (r.d.error || "?"));
      go("reports");
    });
  }
  function dorisk() {
    document.getElementById("ro").textContent = "running v2 risk analysis…";
    api("POST", "/api/v3/sessions/" + SID + "/risk").then(function (r) {
      var d = r.d;
      document.getElementById("ro").textContent = d.error ||
        ("vulns=" + d.vulns + " impact=$" +
         d.financial_impact.total_estimated_cost +
         " violations=" + d.violations.length);
    });
  }
  function v2pay() {
    api("POST", "/api/v3/v2/payload", {
      kind: document.getElementById("pk").value,
      c2_server: document.getElementById("pc").value,
      confirm_text: document.getElementById("px").value,
    }).then(function (r) {
      document.getElementById("po").textContent =
        r.d.error || (r.d.kind + " " + r.d.bytes + " bytes\n" + r.d.code_preview);
    });
  }
  function c2t() {
    var a = document.getElementById("ca").value;
    var c = document.getElementById("cc").value;
    api("POST", "/api/v3/c2/task", { agent_id: a, command: c }).then(function (r) {
      document.getElementById("co").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function c2l(start) {
    if (start) {
      var host = (document.getElementById("ch") || {}).value || "127.0.0.1";
      var port = parseInt((document.getElementById("cp") || {}).value || "4443", 10);
      api("POST", "/api/v3/c2/listener/start", { host: host, port: port })
        .then(function (r) {
          var ok = r.d && r.d.running;
          toast(ok ? "listener started on " + host + ":" + port +
                " (token " + String(r.d.token || "").slice(0, 4) + "…)"
                : "start failed: " + (r.d && r.d.error || "unknown"),
                ok ? "ok" : "err");
          go("c2");
        });
    } else {
      api("POST", "/api/v3/c2/listener/stop", {}).then(function () {
        toast("listener stopped", "ok");
        go("c2");
      });
    }
  }
  function _saveKey(name) {
    var el = document.getElementById("ak-" + name);
    var v = el ? el.value : "";
    if (!v) { toast("enter a value first", "warn"); return; }
    api("POST", "/api/v3/settings/keys", { name: name, value: v })
      .then(function (r) {
        var ok = r.d && r.d.ok;
        toast(ok ? "saved " + name + " (masked " +
              (r.d.key && r.d.key.masked || "") + ")"
              : "save failed: " + (r.d && r.d.error || "unknown"),
              ok ? "ok" : "err");
        go("settings");
      });
  }
  function _delKey(name) {
    api("DELETE", "/api/v3/settings/keys/" + name).then(function (r) {
      var ok = r.d && r.d.ok;
      toast(ok ? "removed " + name + " from keys file"
            : "delete failed: " + (r.d && r.d.error || "unknown"),
            ok ? "ok" : "err");
      go("settings");
    });
  }
  function opswitch() {
    api("POST", "/api/v3/opsec",
        { profile: document.getElementById("op").value }).then(function (r) {
      document.getElementById("oo").textContent =
        r.d.error || JSON.stringify(r.d);
      go("opsec");
    });
  }
  function tornew() {
    api("POST", "/api/v3/opsec/tor-newnym", {}).then(function (r) {
      document.getElementById("op2").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function opaudit() {
    api("POST", "/api/v3/opsec/audit", { session_id: SID }).then(function (r) {
      document.getElementById("op2").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function doh() {
    api("GET", "/api/v3/doh?host=" +
        encodeURIComponent(document.getElementById("dh").value)).then(function (r) {
      document.getElementById("do").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function tcgen() {
    if (!SID) {
      document.getElementById("tc").textContent = "open a session first";
      return;
    }
    api("POST", "/api/v3/track-cover/generate", { session_id: SID }).then(function (r) {
      document.getElementById("tc").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function surfvalidate() {
    document.getElementById("so").textContent = "validating surface…";
    api("POST", "/api/v3/sessions/" + SID + "/surface/validate", {}).then(function (r) {
      document.getElementById("so").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function surf1(i) {
    var c = (window.__surf || [])[i];
    if (!c) return;
    var kind = { param: "xss", sqli_param: "sqli", login: "auth",
      upload: "lfi", redirect_param: "redirect", graphql: "graphql",
      api: "cors" }[c.type] || "xss";
    api("POST", "/api/v3/sessions/" + SID + "/validate-one",
        { kind: kind, url: c.url }).then(function (r) {
      document.getElementById("so").textContent =
        JSON.stringify(r.d, null, 1).slice(0, 2000);
    });
  }

  function _overviewFallback(e) {
    if (_loggingOut) return;
    setTitle("Overview", "degraded · telemetry unavailable");
    var v = document.getElementById("view");
    if (!v) return;
    v.innerHTML = '<div class="card"><h3>Telemetry unavailable</h3>' +
      '<p class="muted">The console loaded, but the telemetry API did not ' +
      "answer. The rest of the deck is still usable.</p>" +
      "<pre>" + esc((e && e.message) || e || "unknown error") + "</pre>" +
      '<div class="row"><button class="button button-primary" ' +
      'onclick="retryBoot()">Retry link</button>' +
      '<button class="button button-ghost" onclick="go(\'dash\')">' +
      "System status</button></div></div>";
  }

  function _bootStalled() {
    if (_bootSettled) return;
    _bootSettled = true;
    showApp();
    _streamState("LOST");
    var v = document.getElementById("view");
    if (v) {
      v.innerHTML = '<div class="card"><h3>Boot stalled</h3>' +
        '<p class="muted">The console initialized but the dashboard API did ' +
        "not answer within 12 seconds. This is usually a stale server process " +
        "or a blocked <code>/api/v3/</code> request.</p>" +
        '<div class="row"><button class="button button-primary" ' +
        'onclick="retryBoot()">Retry link</button>' +
        '<button class="button button-ghost" onclick="logout()">' +
        "Re-authenticate</button></div></div>";
    }
  }

  function retryBoot() {
    location.reload();
  }

  function boot() {
    if (!T) { showLogin(); return Promise.resolve(); }
    _bootSettled = false;
    if (_bootTimer) window.clearTimeout(_bootTimer);
    _bootTimer = window.setTimeout(_bootStalled, 12000);

    function finish() {
      _bootSettled = true;
      if (_bootTimer) window.clearTimeout(_bootTimer);
    }

    return api("GET", "/api/v3/audit").then(function (r) {
      if (r.status === 401) throw new Error("session expired");
      showApp();
      if (r.d && r.d.using_defaults) {
        document.getElementById("warn").innerHTML =
          '<div class="warnbar">Using DEFAULT admin/changeme credentials — ' +
          "set dashboard.users argon2 hashes in config/ardf.yaml</div>";
      }
      return api("GET", "/api/v3/scope").then(function (sr) {
        return sr;
      }, function () {
        return { d: {} };
      });
    }, function () {
      // Audit is informational; a failed audit must not hide the console.
      showApp();
      return api("GET", "/api/v3/scope").then(function (sr) {
        return sr;
      }, function () {
        return { d: {} };
      });
    }).then(function (r) {
      if (r.status === 401) throw new Error("session expired");
      if (r.d && !r.d.error) {
        _applyScope(r.d);
      } else {
        var sb = document.getElementById("scopebadge");
        if (sb) { sb.textContent = "SCOPE ?"; sb.className = "badge warn"; }
        var sf = document.getElementById("footer-scope");
        if (sf) sf.textContent = "UNKNOWN";
      }
      var uh = document.getElementById("user-hud");
      if (uh) uh.textContent = USER || "operator";
      nav();
      _refreshApprovals();
      _fallbackPoll();
      _streamState("SYNC");
      _connectStream();
      window.setInterval(_fallbackPoll, 30000);
      return views.overview().catch(function (e) {
        _overviewFallback(e);
      });
    }).then(finish, function (e) {
      finish();
      if (!_loggingOut) {
        showApp();
        _overviewFallback(e);
      }
    });
  }

  // expose handlers used by inline onclick attributes
  window.go = go;
  window.c2l = c2l;
  window._saveKey = _saveKey;
  window._delKey = _delKey;
  window.login = login;
  window.logout = logout;
  window.quick = quick;
  window.scopeadd = scopeadd;
  window.scopedel = scopedel;
  window.scopetoggle = scopetoggle;
  window.newsess = newsess;
  window.pick = pick;
  window.delsess = delsess;
  window.fact = fact;
  window.fvalidate = fvalidate;
  window.fexploit = fexploit;
  window.termClear = termClear;
  window.atrun = atrun;
  window.egress = egress;
  window.joblog = joblog;
  window.jobstream = jobstream;
  window.jobkill = jobkill;
  window.decide = decide;
  window.doverify = doverify;
  window.doenrich = doenrich;
  window.doloot = doloot;
  window.autoexploit = autoexploit;
  window.mkpdf = mkpdf;
  window.dorisk = dorisk;
  window.v2pay = v2pay;
  window.surfvalidate = surfvalidate;
  window.surf1 = surf1;
  function chainrun(id) {
    if (!SID) {
      document.getElementById("ct").textContent = "open a session first";
      return;
    }
    var spec = {};
    try {
      spec = JSON.parse(document.getElementById("chspec").value || "{}");
    } catch (e) {
      document.getElementById("ct").textContent = "bad spec JSON";
      return;
    }
    document.getElementById("ct").textContent = "running " + id + "…";
    api("POST", "/api/v3/chains/run", {
      session_id: SID, chain: id, spec: spec,
      confirm_text: document.getElementById("chconf").value,
    }).then(function (r) {
      document.getElementById("ct").textContent =
        JSON.stringify(r.d, null, 1).slice(0, 4000);
    });
  }
  function reconrun(name) {
    document.getElementById("rx").textContent = "running " + name + "…";
    api("POST", "/api/v3/sessions/" + SID + "/recon/" + name, {}).then(function (r) {
      document.getElementById("rx").textContent =
        JSON.stringify(r.d, null, 1).slice(0, 3000);
    });
  }
  window.reconrun = reconrun;
  window.chainrun = chainrun;
  window.opswitch = opswitch;
  window.tornew = tornew;
  window.opaudit = opaudit;
  window.doh = doh;
  function brutelists() {
    api("GET", "/api/v3/brute-lists").then(function (r) {
      document.getElementById("bl").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function pdbpreview() {
    var c = document.getElementById("pc").value;
    api("GET", "/api/v3/payloaddb/query?category=" + encodeURIComponent(c) +
        "&limit=15").then(function (r) {
      document.getElementById("po2").textContent =
        (r.d.payloads || []).join("\n").slice(0, 2000);
    });
  }
  function pdbexport() {
    var c = document.getElementById("pc").value;
    api("POST", "/api/v3/payloaddb/export", { category: c, limit: 2000 }).then(function (r) {
      document.getElementById("po2").textContent = JSON.stringify(r.d, null, 1);
    });
  }
  function pdbfuzz() {
    if (!SID) {
      document.getElementById("po2").textContent = "open a session first";
      return;
    }
    var c = document.getElementById("pc").value;
    document.getElementById("po2").textContent = "fuzzing " + c + "…";
    api("POST", "/api/v3/fuzz",
        { session_id: SID, category: c, max_requests: 60 }).then(function (r) {
      document.getElementById("po2").textContent =
        JSON.stringify(r.d, null, 1).slice(0, 2000);
    });
  }
  window.brutelists = brutelists;
  window.pdbpreview = pdbpreview;
  window.pdbexport = pdbexport;
  window.pdbfuzz = pdbfuzz;
  window.openPalette = openPalette;
  window.paletteFilter = paletteFilter;
  window.closePalette = closePalette;
  window.paletteRun = paletteRun;
  window.modFilter = modFilter;
  window.modSearch = modSearch;
  window.modPick = modPick;
  window.modRun = modRun;
  window.atSelChange = atSelChange;
  window.ovQuick = ovQuick;
  window.toggleTheme = toggleTheme;
  window.retryBoot = retryBoot;

  // Palette backdrop click
  var _pal = document.getElementById("palette");
  if (_pal) {
    _pal.addEventListener("click", function (e) {
      if (e.target === _pal) closePalette();
    });
  }

  applyTheme(THEME);
  var _bd = document.getElementById("boot-diag");
  if (_bd) _bd.classList.add("hidden");
  window.__ardfReady = true;
  window.__ardfBuild = "3.1.1";

  if (!T) {
    showLogin();
  } else {
    boot();
  }
})();
