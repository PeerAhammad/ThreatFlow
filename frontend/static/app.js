(() => {
  "use strict";

  const MAXW = 400; // flows kept on screen
  const $ = (id) => document.getElementById(id);

  const S = {
    p: [], regime: [], rate: [], alert: [], y: [],
    flows: 0, flags: 0, eps: 0, lastAlert: 0,
    thr: 0.5,
    cfg: { window: 10, on_rate: 0.2, hold: 30, on_count: 2 },
    dirty: true,
  };
  let ws = null;
  const send = (o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };

  // ---------- helpers ----------
  const h = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };
  const setClass = (el, base, state) => { el.className = base + " " + state; };

  // ---------- connection ----------
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws/replay`);
    ws.onopen = () => {
      const c = $("conn");
      c.textContent = "connected"; c.className = "pill on";
    };
    ws.onclose = () => {
      const c = $("conn");
      c.textContent = "reconnecting\u2026"; c.className = "pill off";
      setTimeout(connect, 1500);
    };
    ws.onmessage = (e) => handle(JSON.parse(e.data));
  }

  function handle(m) {
    if (m.type === "hello") {
      S.thr = m.flag_thr; S.cfg = m.alert;
      renderStatic(); clearState();
    } else if (m.type === "reset") {
      clearState();
    } else if (m.type === "batch") {
      onBatch(m);
    } else if (m.type === "done") {
      markRunning(false);
    }
  }

  // ---------- state ----------
  function clearState() {
    S.p = []; S.regime = []; S.rate = []; S.alert = []; S.y = [];
    S.flows = 0; S.flags = 0; S.eps = 0; S.lastAlert = 0;
    renderCounters(); renderNow(null); S.dirty = true;
  }

  function onBatch(m) {
    const n = m.p.length;
    if (!n) return;
    for (let i = 0; i < n; i++) {
      S.flows++;
      if (m.p[i] >= S.thr) S.flags++;
      if (m.alert[i] === 1 && S.lastAlert === 0) S.eps++;
      S.lastAlert = m.alert[i];
    }
    for (const k of ["p", "regime", "rate", "alert", "y"]) {
      S[k].push(...m[k]);
      if (S[k].length > MAXW) S[k] = S[k].slice(-MAXW);
    }
    renderCounters();
    renderNow({
      p: m.p[n - 1], regime: m.regime[n - 1], rate: m.rate[n - 1],
      alert: m.alert[n - 1], silence: m.silence[n - 1],
    });
    S.dirty = true;
  }

  // ---------- text / cards ----------
  function renderStatic() {
    $("thr").textContent = S.thr.toFixed(2);
    $("win").textContent = S.cfg.window;
    $("svg-alert").textContent = `\u2265${S.cfg.on_count} flags in ${S.cfg.window}, hold ${S.cfg.hold}`;
  }

  function renderCounters() {
    $("c-flows").textContent = S.flows.toLocaleString();
    $("c-flags").textContent = S.flags.toLocaleString();
    $("c-eps").textContent = S.eps.toLocaleString();
    $("c-comp").textContent = S.eps > 0 ? `${Math.round(S.flags / S.eps).toLocaleString()} : 1` : "\u2014";
  }

  function renderNow(r) {
    const { window: win, hold, on_count } = S.cfg;
    if (!r) {
      $("p-now").textContent = "0.000"; $("p-now").className = "big";
      $("regime").textContent = "0.00"; setClass($("regime"), "big", "off");
      $("alert-state").textContent = "OFF"; setClass($("alert-state"), "big", "off");
      $("hold-bar").style.width = "0%";
      $("hold-text").textContent = `Triggers at \u2265${on_count} flagged flows within ${win}`;
      $("threat").textContent = "LOW"; setClass($("threat"), "big", "low");
      $("threat-card").className = "card";
      return;
    }
    $("p-now").textContent = r.p.toFixed(3);
    $("p-now").className = "big" + (r.p >= S.thr ? " attack" : "");

    $("regime").textContent = r.regime.toFixed(2);
    setClass($("regime"), "big", r.regime >= 0.5 ? "attack" : "off");

    const on = r.alert === 1;
    $("alert-state").textContent = on ? "ON" : "OFF";
    setClass($("alert-state"), "big", on ? "on" : "off");
    if (on) {
      $("hold-bar").style.width = `${Math.min(1, r.silence / hold) * 100}%`;
      $("hold-text").textContent = `Holding: ${Math.min(r.silence, hold)}/${hold} quiet flows before the alert clears`;
    } else {
      $("hold-bar").style.width = "0%";
      $("hold-text").textContent = `Triggers at \u2265${on_count} flagged flows within ${win}`;
    }

    const level = on ? "high" : r.rate > 0 ? "medium" : "low";
    $("threat").textContent = level.toUpperCase();
    setClass($("threat"), "big", level);
    $("threat-card").className = "card" + (level === "low" ? "" : " " + level);
  }

  // ---------- charts ----------
  function setup(c) {
    const r = c.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = Math.max(300, Math.floor(r.width) || 600);
    const hh = Math.floor(r.height) || 150;
    const pw = Math.floor(w * dpr), ph = Math.floor(hh * dpr);
    if (c.width !== pw || c.height !== ph) { c.width = pw; c.height = ph; }
    const g = c.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, hh);
    return { g, w, h: hh };
  }
  const X = (i, n, w) => ((MAXW - n + i) / (MAXW - 1)) * w;
  const Y = (v, hh) => 8 + (1 - v) * (hh - 16);

  function hline(g, w, hh, v, color) {
    const y = Y(v, hh);
    g.save();
    g.strokeStyle = color; g.lineWidth = 1; g.setLineDash([5, 4]);
    g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke();
    g.restore();
  }

  function tag(g, hh, v, color, label) {
    const y = Y(v, hh);
    g.font = "11px system-ui, sans-serif";
    const tw = g.measureText(label).width;
    g.fillStyle = "#161b22"; g.fillRect(4, y - 16, tw + 8, 14);
    g.fillStyle = color; g.fillText(label, 8, y - 5);
  }

  function line(g, arr, w, hh, color, fill) {
    const n = arr.length;
    if (!n) return;
    g.beginPath();
    arr.forEach((v, i) => { const x = X(i, n, w), y = Y(v, hh); if (i) g.lineTo(x, y); else g.moveTo(x, y); });
    g.strokeStyle = color; g.lineWidth = 1.6; g.stroke();
    if (fill) {
      g.lineTo(X(n - 1, n, w), Y(0, hh)); g.lineTo(X(0, n, w), Y(0, hh)); g.closePath();
      g.fillStyle = fill; g.fill();
    }
  }

  function truth(g, w, hh) {
    if (!$("truth").checked) return;
    const n = S.y.length, bw = Math.max(1.5, w / MAXW);
    g.fillStyle = "#58a6ff";
    for (let i = 0; i < n; i++) if (S.y[i] === 1) g.fillRect(X(i, n, w) - bw / 2, hh - 5, bw, 5);
  }

  function drawFlow() {
    const { g, w, h: hh } = setup($("ch-flow"));
    hline(g, w, hh, S.thr, "#d29922");
    line(g, S.p, w, hh, "#8b949e");
    const n = S.p.length;
    g.fillStyle = "#f85149";
    S.p.forEach((v, i) => {
      if (v >= S.thr) { g.beginPath(); g.arc(X(i, n, w), Y(v, hh), 2.4, 0, Math.PI * 2); g.fill(); }
    });
    truth(g, w, hh);
    tag(g, hh, S.thr, "#d29922", `flag threshold ${S.thr}`);
  }

  function drawRegime() {
    const { g, w, h: hh } = setup($("ch-regime"));
    hline(g, w, hh, 0.5, "#8b949e");
    line(g, S.regime, w, hh, "#bc8cff", "rgba(188,140,255,0.15)");
    truth(g, w, hh);
    tag(g, hh, 0.5, "#8b949e", "0.5");
  }

  function drawAlert() {
    const { g, w, h: hh } = setup($("ch-alert"));
    const n = S.alert.length;
    let start = -1;
    for (let i = 0; i <= n; i++) {
      const on = i < n && S.alert[i] === 1;
      if (on && start < 0) start = i;
      if (!on && start >= 0) {
        const x0 = X(start, n, w), x1 = X(i - 1, n, w) + w / MAXW;
        g.fillStyle = "rgba(248,81,73,0.28)";
        g.fillRect(x0, 0, x1 - x0, hh);
        start = -1;
      }
    }
    hline(g, w, hh, S.cfg.on_rate, "#d29922");
    line(g, S.rate, w, hh, "#d29922");
    truth(g, w, hh);
    tag(g, hh, S.cfg.on_rate, "#d29922", `trigger ${Math.round(S.cfg.on_rate * 100)}%`);
  }

  function frame() {
    if (S.dirty) { S.dirty = false; drawFlow(); drawRegime(); drawAlert(); }
    requestAnimationFrame(frame);
  }

  // ---------- evaluation panel ----------
  function renderEval(ev) {
    const box = $("eval");
    box.replaceChildren();
    if (!ev || !ev.models) return;
    box.append(h("h2", "Held-out evaluation"));
    if (ev.dataset) box.append(h("p", ev.dataset, "hint"));

    const t = h("table");
    const head = h("tr");
    ["Model", "Precision", "Recall", "F1", "AUC"].forEach((x) => head.append(h("th", x)));
    t.append(head);
    ev.models.forEach((m) => {
      const r = h("tr");
      r.append(h("td", m.name));
      [m.precision, m.recall, m.f1, m.auc].forEach((v) => r.append(h("td", Number(v).toFixed(2) + "%")));
      t.append(r);
    });
    box.append(t);

    const a = ev.alert;
    if (a) {
      const tiles = h("div", null, "tiles");
      [
        [`${a.flagged_flows} \u2192 ${a.episodes}`, "flagged flows \u2192 alert episodes"],
        [String(a.incidents), "incidents detected"],
        [String(a.coverage), "attack-flow coverage"],
        [String(a.false_episodes), "false alert episodes"],
      ].forEach(([b, s]) => { const d = h("div", null, "tile"); d.append(h("b", b), h("span", s)); tiles.append(d); });
      box.append(tiles);
      if (a.scope) box.append(h("p", `Alert layer: ${a.scope}. Incident merge distance ${a.margin} flows.`, "hint"));
    }
    if (ev.note) box.append(h("p", ev.note, "hint"));
  }

  // ---------- controls ----------
  function markRunning(on) {
    $("btn-start").classList.toggle("active", on);
    $("btn-pause").classList.toggle("active", !on);
  }
  $("btn-start").onclick = () => { send({ cmd: "speed", value: Number($("speed").value) }); send({ cmd: "start" }); markRunning(true); };
  $("btn-pause").onclick = () => { send({ cmd: "pause" }); markRunning(false); };
  $("btn-reset").onclick = () => { send({ cmd: "reset" }); markRunning(false); };
  $("speed").onchange = () => send({ cmd: "speed", value: Number($("speed").value) });
  $("truth").onchange = () => { S.dirty = true; };
  window.addEventListener("resize", () => { S.dirty = true; });

  // ---------- boot ----------
  renderStatic(); renderCounters(); renderNow(null); markRunning(false);
  fetch("/api/status").then((r) => r.json()).then((s) => {
    if (s.flag_threshold !== undefined) S.thr = s.flag_threshold;
    renderStatic(); renderEval(s.eval);
  }).catch(() => {});
  connect();
  requestAnimationFrame(frame);
})();
