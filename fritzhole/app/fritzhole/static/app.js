/* FritzHole Dashboard – alle URLs relativ (Home Assistant Ingress). */
"use strict";

const STATUS = {
  allowed: "Erlaubt", blocked: "Blockiert", nxdomain: "NXDOMAIN", error: "Fehler", no_answer: "Keine Antwort",
};
const STATE = {
  running: "Mitschnitt aktiv", connecting: "Verbinde …", backoff: "Neuverbindung …",
  auth_error: "Anmeldung fehlgeschlagen", unconfigured: "Nicht konfiguriert", stopped: "Gestoppt", error: "Fehler",
};
const $ = (id) => document.getElementById(id);
const fmtN = new Intl.NumberFormat("de-DE");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let devices = [];
let activeTab = "overview";
const an = { q: "", status: "", device_id: "", oldest: null };
const live = { paused: false, rows: [], es: null, lastId: 0, pollTimer: null, failures: 0 };

// ------------------------------------------------------------------ helpers
async function api(path, params = {}, opts = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== "" && v !== null && v !== undefined) qs.set(k, v);
  const url = "api/" + path + (qs.toString() ? "?" + qs : "");
  const method = (opts.method || "GET").toUpperCase();
  const headers = { ...(opts.headers || {}) };
  if (method !== "GET") headers["X-FritzHole-Confirm"] = "1";  // Pflicht-Header für Schreibzugriffe
  const r = await fetch(url, { cache: "no-store", ...opts, headers });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { const j = await r.json(); msg = j.detail || msg; } catch (_) { /* kein JSON */ }
    const err = new Error(msg); err.status = r.status; throw err;
  }
  return r.json();
}
const rangeSec = () => Number($("range").value);
const fromTs = () => Date.now() / 1000 - rangeSec();
function fmtTime(ts, withDate) {
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString("de-DE");
  return withDate ? d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) + " " + t : t;
}
const pct = (v) => (v || 0).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " %";
const badge = (s) => `<span class="badge ${esc(s)}">${esc(STATUS[s] || s)}</span>`;
function deviceLabel(e) {
  const n = e.device_name;
  return n ? `${esc(n)} <span class="ips">${esc(e.client_ip)}</span>` : esc(e.client_ip);
}

// ------------------------------------------------------------------ tabs
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
function showTab(name) {
  activeTab = name;
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + name));
  refresh();
}

// ------------------------------------------------------------------ status
async function loadStatus() {
  try {
    const st = await api("status");
    const c = st.capture || {};
    const pill = $("capState");
    pill.className = "pill " + (c.state || "");
    pill.textContent = STATE[c.state] || c.state || "?";
    const banner = $("banner");
    if (c.state === "unconfigured") {
      banner.textContent = "FRITZ!Box-Zugangsdaten fehlen. Bitte in Home Assistant unter Einstellungen → Apps → FritzHole → Konfiguration eintragen und die App neu starten.";
      banner.classList.remove("hidden");
    } else if (c.state === "auth_error" || (c.state === "backoff" && c.last_error)) {
      banner.textContent = "Mitschnitt: " + c.last_error;
      banner.classList.remove("hidden");
    } else banner.classList.add("hidden");
    if (activeTab === "status") renderStatus(st);
  } catch (e) {
    $("capState").textContent = "Backend nicht erreichbar";
  }
}
function kv(el, rows) {
  el.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v ?? "–")}</dd>`).join("");
}
function renderStatus(st) {
  const c = st.capture || {}, s = c.stats || {}, cfg = st.config || {};
  kv($("stCapture"), [
    ["Zustand", STATE[c.state] || c.state], ["Letzter Fehler", c.last_error],
    ["Verbunden seit", c.connected_since ? fmtTime(c.connected_since, true) : null],
    ["Nächster Versuch", c.next_retry ? fmtTime(c.next_retry, true) : null],
    ["FRITZ!Box", cfg.fritzbox_host], ["Interface", c.interface],
    ["PCAP-Format / Linktype", `${c.pcap_variant ?? "–"} / ${c.linktype ?? "–"}`],
    ["Sessions", c.sessions], ["TCP-DNS", c.tcp_dns ? "aktiv (experimentell)" : "deaktiviert"],
    ["Frames", fmtN.format(s.frames || 0)], ["DNS-Nachrichten", fmtN.format(s.dns || 0)],
    ["Ereignisse", fmtN.format(s.events || 0)], ["Ohne passende Anfrage", fmtN.format(s.unmatched || 0)],
    ["Duplikate verworfen", fmtN.format(s.duplicates || 0)], ["Fehlerhafte Pakete", fmtN.format(s.malformed || 0)],
    ["Abgeschnitten (Snaplen)", fmtN.format(s.truncated || 0)], ["Fragmente", fmtN.format(s.fragments || 0)],
    ["TCP-Flows verworfen", fmtN.format(s.tcp_dropped_flows || 0)],
  ]);
  const db = st.database || {}, w = st.writer || {}, h = st.hostnames;
  kv($("stDb"), [
    ["Version", st.version], ["Ereignisse gespeichert", fmtN.format(db.events || 0)],
    ["Ältestes Ereignis", db.oldest ? fmtTime(db.oldest, true) : null],
    ["Datenbankgröße", ((db.size_bytes || 0) / 1048576).toFixed(1) + " MB"],
    ["Aufbewahrung", (cfg.retention_days ?? "–") + " Tage / max. " + fmtN.format(cfg.max_events || 0)],
    ["Letzte Bereinigung", w.last_cleanup ? fmtTime(w.last_cleanup, true) : null],
    ["Warteschlange / verworfen", `${w.queue ?? 0} / ${w.dropped ?? 0}`],
    ["Gerätenamen (TR-064)", h ? `${h.state}${h.count ? ", " + h.count + " Hosts" : ""}${h.last_error ? " – " + h.last_error : ""}` : "deaktiviert"],
    ["Live-Verbindungen", st.live_clients],
  ]);
}

// ------------------------------------------------------------------ overview
async function loadOverview() {
  const p = { from_ts: fromTs() };
  const [s, tl, tb, td, tdev] = await Promise.all([
    api("summary", p), api("timeline", p), api("top/domains", { ...p, status: "blocked", limit: 10 }),
    api("top/domains", { ...p, limit: 10 }), api("top/devices", { ...p, limit: 10 }),
  ]);
  $("kTotal").textContent = fmtN.format(s.total);
  $("kBlocked").textContent = fmtN.format(s.blocked);
  $("kRate").textContent = pct(s.block_rate);
  $("kAllowed").textContent = fmtN.format(s.allowed);
  $("kErrors").textContent = fmtN.format(s.errors);
  $("kNoAnswer").textContent = s.no_answer ? fmtN.format(s.no_answer) + " ohne Antwort" : "";
  drawChart($("chart"), tl);
  domainTable($("ovTopBlocked"), tb, true);
  domainTable($("ovTopDomains"), td, false);
  deviceTable($("ovTopDevices"), tdev, true);
}

function domainTable(el, rows, blockedOnly) {
  if (!rows.length) { el.innerHTML = `<tr><td class="muted">Keine Daten im Zeitraum</td></tr>`; return; }
  el.innerHTML = `<tr><th>Domain</th><th class="num">Anfragen</th>${blockedOnly ? "" : '<th class="num">Blockiert</th>'}</tr>` +
    rows.map((r) => `<tr><td class="dom"><a data-domain="${esc(r.domain)}">${esc(r.domain)}</a></td>
      <td class="num">${fmtN.format(r.count)}</td>${blockedOnly ? "" : `<td class="num">${fmtN.format(r.blocked)}</td>`}</tr>`).join("");
}
function deviceTable(el, rows, compact) {
  if (!rows.length) { el.innerHTML = `<tr><td class="muted">Keine Daten im Zeitraum</td></tr>`; return; }
  el.innerHTML = `<tr><th>Gerät</th><th class="num">Anfragen</th><th class="num">Blockiert</th><th>Rate</th></tr>` +
    rows.map((r) => {
      const name = r.device_name || (r.ips[0] ?? "?");
      const ips = compact ? "" : `<div class="ips">${esc(r.ips.join(", "))}${r.mac ? " · " + esc(r.mac) : ""}</div>`;
      return `<tr><td><a data-device="${r.device_id}">${esc(name)}</a>${ips}</td><td class="num">${fmtN.format(r.count)}</td>
        <td class="num">${fmtN.format(r.blocked)}</td>
        <td title="${pct(r.block_rate)}"><div class="bar"><i style="width:${Math.min(100, r.block_rate).toFixed(1)}%"></i></div></td></tr>`;
    }).join("");
}
document.addEventListener("click", (ev) => {
  const a = ev.target.closest("a[data-domain], a[data-device]");
  if (!a) return;
  ev.preventDefault();
  if (a.dataset.domain) { an.q = a.dataset.domain; $("anSearch").value = an.q; }
  if (a.dataset.device) { an.device_id = a.dataset.device; $("anDevice").value = an.device_id; }
  showTab("analysis");
});

// ------------------------------------------------------------------ chart
function drawChart(el, tl) {
  const W = el.clientWidth || 600, H = el.clientHeight || 220, padL = 44, padB = 22, padT = 8, padR = 6;
  const n = tl.points.length;
  const keys = ["allowed", "blocked", "errors"];
  const colors = { allowed: "var(--allowed)", blocked: "var(--blocked)", errors: "var(--error)" };
  const totals = tl.points.map((_, i) => keys.reduce((a, k) => a + tl.series[k][i], 0));
  const max = Math.max(1, ...totals);
  const nice = niceMax(max);
  const bw = (W - padL - padR) / Math.max(1, n);
  const y = (v) => padT + (H - padT - padB) * (1 - v / nice);
  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="DNS-Anfragen im Zeitverlauf">`;
  for (let i = 0; i <= 4; i++) {
    const v = (nice / 4) * i, yy = y(v);
    svg += `<line class="grid" x1="${padL}" x2="${W - padR}" y1="${yy}" y2="${yy}"/>`;
    svg += `<text class="axis" x="${padL - 6}" y="${yy + 4}" text-anchor="end">${fmtN.format(Math.round(v))}</text>`;
  }
  const gap = bw > 4 ? 1 : 0;
  for (let i = 0; i < n; i++) {
    let base = 0;
    for (const k of keys) {
      const v = tl.series[k][i];
      if (!v) continue;
      const y1 = y(base + v), y0 = y(base);
      svg += `<rect x="${padL + i * bw + gap / 2}" y="${y1}" width="${Math.max(0.5, bw - gap)}" height="${Math.max(0.5, y0 - y1)}" fill="${colors[k]}" data-i="${i}"/>`;
      base += v;
    }
    svg += `<rect x="${padL + i * bw}" y="${padT}" width="${bw}" height="${H - padT - padB}" fill="transparent" data-i="${i}"/>`;
  }
  const ticks = Math.min(6, n);
  for (let t = 0; t < ticks; t++) {
    const i = Math.round((t * (n - 1)) / Math.max(1, ticks - 1));
    const long = tl.bucket >= 3600 && rangeSec() > 86400;
    svg += `<text class="axis" x="${padL + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${esc(axisLabel(tl.points[i], long))}</text>`;
  }
  el.innerHTML = svg + "</svg>";
  const tip = $("tooltip");
  el.onmousemove = (e) => {
    const i = e.target.dataset ? e.target.dataset.i : undefined;
    if (i === undefined) { tip.classList.add("hidden"); return; }
    const k = Number(i);
    tip.innerHTML = `<b>${esc(fmtTime(tl.points[k], true))}</b><br>Erlaubt: ${fmtN.format(tl.series.allowed[k])}<br>` +
      `Blockiert: ${fmtN.format(tl.series.blocked[k])}<br>Fehler: ${fmtN.format(tl.series.errors[k])}`;
    tip.style.left = Math.min(e.clientX + 12, window.innerWidth - 170) + "px";
    tip.style.top = e.clientY + 12 + "px";
    tip.classList.remove("hidden");
  };
  el.onmouseleave = () => tip.classList.add("hidden");
}
function niceMax(v) {
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function axisLabel(ts, long) {
  const d = new Date(ts * 1000);
  return long ? d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" })
    : d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
}

// ------------------------------------------------------------------ events table
function eventRow(e, isNew) {
  const lat = e.latency_ms != null ? e.latency_ms.toFixed(1) + " ms" : "";
  return `<tr class="${isNew ? "new" : ""}"><td>${esc(fmtTime(e.ts, rangeSec() > 86400))}</td><td>${badge(e.status)}</td>
    <td class="dom"><a data-domain="${esc(e.qname)}">${esc(e.qname)}</a> <span class="mark" data-mark="${esc(e.qname)}">${markHtml(e.qname)}</span></td><td>${esc(e.qtype)}</td>
    <td>${deviceLabel(e)}</td><td class="dom opt">${esc(e.answers)}</td><td class="num opt">${esc(lat)}</td>
    <td class="opt muted">${esc(e.transport)}</td>
    <td class="act"><button class="icon-btn" data-menu="${esc(e.qname)}" data-st="${esc(e.status)}" title="Domain verwalten" aria-label="Domain verwalten">⋯</button></td></tr>`;
}
const EVENT_HEAD = `<tr><th>Zeit</th><th>Status</th><th>Domain</th><th>Typ</th><th>Gerät / Client</th>
  <th class="opt">Antwort</th><th class="num opt">Latenz</th><th class="opt">Proto</th><th class="act"></th></tr>`;

// ------------------------------------------------------------------ live
function liveFilter() {
  return { q: $("liveSearch").value.trim(), status: $("liveStatus").value, device_id: $("liveDevice").value };
}
function matchesLive(e) {
  const f = liveFilter();
  if (f.status && e.status !== f.status) return false;
  if (f.device_id && String(e.device_id) !== f.device_id) return false;
  if (f.q) { const q = f.q.toLowerCase(); if (!e.qname.includes(q) && !e.client_ip.includes(q)) return false; }
  return true;
}
async function loadLive() {
  const rows = await api("events", { ...liveFilter(), limit: 200 });
  live.rows = rows;
  live.lastId = Math.max(live.lastId, ...rows.map((r) => r.id), 0);
  renderLive();
}
function renderLive(newIds = new Set()) {
  $("liveTable").innerHTML = EVENT_HEAD + (live.rows.length ? live.rows.map((e) => eventRow(e, newIds.has(e.id))).join("")
    : `<tr><td colspan="9" class="muted">Noch keine Ereignisse – sobald Geräte DNS-Anfragen stellen, erscheinen sie hier.</td></tr>`);
}
function onLiveEvents(evts) {
  live.lastId = Math.max(live.lastId, ...evts.map((e) => e.id));
  if (live.paused || activeTab !== "live") return;
  const fresh = evts.filter(matchesLive);
  if (!fresh.length) return;
  live.rows = fresh.reverse().concat(live.rows).slice(0, 300);
  renderLive(new Set(fresh.map((e) => e.id)));
}
function connectStream() {
  if (!window.EventSource || live.failures >= 3) return startPolling();
  const es = new EventSource("api/stream");
  live.es = es;
  live.lastMsg = Date.now();
  es.addEventListener("dns", (m) => { live.failures = 0; live.lastMsg = Date.now(); onLiveEvents([JSON.parse(m.data)]); });
  es.addEventListener("ping", () => { live.lastMsg = Date.now(); });
  es.onopen = () => { live.lastMsg = Date.now(); $("liveConn").textContent = "● live (SSE)"; };
  // Watchdog: puffert ein Proxy den Stream, kommen keine Pings an -> Polling
  live.watch = setInterval(() => {
    if (live.es && Date.now() - live.lastMsg > 45000) {
      live.es.close(); live.es = null; clearInterval(live.watch); startPolling();
    }
  }, 10000);
  es.onerror = () => {
    live.failures++;
    $("liveConn").textContent = "Verbindung unterbrochen …";
    if (live.failures >= 3) { es.close(); live.es = null; startPolling(); }
  };
}
function startPolling() {
  if (live.pollTimer) return;
  $("liveConn").textContent = "● live (Polling)";
  live.pollTimer = setInterval(async () => {
    try {
      const rows = await api("events", { after_id: live.lastId, limit: 500 });
      if (rows.length) onLiveEvents(rows);
    } catch (e) { $("liveConn").textContent = "Backend nicht erreichbar"; }
  }, 3000);
}
$("livePause").addEventListener("click", () => {
  live.paused = !live.paused;
  $("livePause").textContent = live.paused ? "Fortsetzen" : "Pause";
  if (!live.paused) loadLive();
});
let liveDeb;
["liveSearch", "liveStatus", "liveDevice"].forEach((id) => $(id).addEventListener("input", () => {
  clearTimeout(liveDeb); liveDeb = setTimeout(loadLive, 250);
}));

// ------------------------------------------------------------------ analysis
function anParams() {
  return { from_ts: fromTs(), q: an.q, status: an.status, device_id: an.device_id };
}
async function loadAnalysis() {
  const p = anParams();
  const [s, tb, td, dev, ev] = await Promise.all([
    api("summary", p), api("top/domains", { ...p, status: "blocked", limit: 15 }),
    api("top/domains", { ...p, limit: 15 }), api("top/devices", { ...p, limit: 50 }), api("events", { ...p, limit: 100 }),
  ]);
  $("anKpis").innerHTML = [["Anfragen", fmtN.format(s.total)], ["Blockiert", fmtN.format(s.blocked)],
    ["Rate", pct(s.block_rate)], ["Fehler", fmtN.format(s.errors)], ["Domains", fmtN.format(s.domains)],
    ["Geräte", fmtN.format(s.devices)]].map(([k, v]) => `<div class="kpi"><span>${k}</span><b>${v}</b></div>`).join("");
  domainTable($("anTopBlocked"), tb, true);
  domainTable($("anTopDomains"), td, false);
  deviceTable($("anDevices"), dev, false);
  $("anEvents").innerHTML = EVENT_HEAD + (ev.length ? ev.map((e) => eventRow(e)).join("")
    : `<tr><td colspan="9" class="muted">Keine Treffer</td></tr>`);
  an.oldest = ev.length ? ev[ev.length - 1].id : null;
  $("anMore").classList.toggle("hidden", ev.length < 100);
}
$("anMore").addEventListener("click", async () => {
  const ev = await api("events", { ...anParams(), limit: 100, before_id: an.oldest });
  $("anEvents").insertAdjacentHTML("beforeend", ev.map((e) => eventRow(e)).join(""));
  if (ev.length) an.oldest = ev[ev.length - 1].id;
  $("anMore").classList.toggle("hidden", ev.length < 100);
});
let anDeb;
$("anSearch").addEventListener("input", () => { clearTimeout(anDeb); anDeb = setTimeout(() => { an.q = $("anSearch").value.trim(); loadAnalysis(); }, 300); });
$("anStatus").addEventListener("change", () => { an.status = $("anStatus").value; loadAnalysis(); });
$("anDevice").addEventListener("change", () => { an.device_id = $("anDevice").value; loadAnalysis(); });
$("anReset").addEventListener("click", () => {
  an.q = an.status = an.device_id = "";
  $("anSearch").value = ""; $("anStatus").value = ""; $("anDevice").value = "";
  loadAnalysis();
});

// ------------------------------------------------------------------ devices
async function loadDevices() {
  devices = await api("devices");
  const active = devices.filter((d) => !d.merged_into);
  const opts = `<option value="">Alle Geräte</option>` +
    active.map((d) => `<option value="${d.id}">${esc(d.display_name)}</option>`).join("");
  document.querySelectorAll(".deviceSel").forEach((s) => { const v = s.value; s.innerHTML = opts; s.value = v; });
  if (activeTab !== "devices") return;
  const byId = Object.fromEntries(devices.map((d) => [d.id, d]));
  $("devTable").innerHTML = `<tr><th>Name</th><th>Erkannt als</th><th>Adressen</th><th>Zuletzt gesehen</th><th>Zuordnung</th></tr>` +
    devices.map((d) => {
      const ident = d.mac ? "MAC " + d.mac + (d.shared ? " (geteilt – Router/Repeater?)" : "") : "nur IP";
      const merged = d.merged_into
        ? `→ ${esc(byId[d.merged_into]?.display_name ?? d.merged_into)} <button class="btn ghost small" data-unmerge="${d.id}">Lösen</button>`
        : `<select data-merge="${d.id}"><option value="">Zusammenführen mit …</option>${active.filter((o) => o.id !== d.id)
          .map((o) => `<option value="${o.id}">${esc(o.display_name)}</option>`).join("")}</select>`;
      return `<tr><td><input type="text" value="${esc(d.name || "")}" placeholder="${esc(d.auto_name || "Name vergeben")}" data-rename="${d.id}" maxlength="64"></td>
        <td>${esc(ident)}${d.auto_name ? `<div class="ips">FRITZ!Box: ${esc(d.auto_name)}</div>` : ""}</td>
        <td class="ips">${esc(d.ips.slice(0, 6).map((i) => i.ip).join(", "))}${d.ips.length > 6 ? " …" : ""}</td>
        <td>${d.last_seen ? esc(fmtTime(d.last_seen, true)) : "–"}</td><td>${merged}</td></tr>`;
    }).join("");
}
$("devTable").addEventListener("change", async (ev) => {
  const t = ev.target;
  try {
    if (t.dataset.rename) {
      await api("devices/" + t.dataset.rename, {}, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: t.value }) });
    } else if (t.dataset.merge && t.value) {
      const target = devices.find((d) => String(d.id) === t.value);
      if (!confirm(`Gerät mit „${target.display_name}“ zusammenführen? Bisherige Ereignisse werden übertragen.`)) { t.value = ""; return; }
      await api(`devices/${t.dataset.merge}/merge`, {}, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_id: Number(t.value) }) });
    }
    loadDevices();
  } catch (e) { alert("Fehler: " + e.message); }
});
$("devTable").addEventListener("click", async (ev) => {
  const id = ev.target.dataset.unmerge;
  if (!id) return;
  await api(`devices/${id}/unmerge`, {}, { method: "POST" });
  loadDevices();
});

// ------------------------------------------------------------------ DNS-Filter (FRITZ!Box)
const df = { state: null, offset: 0, loading: null, resumePoll: null };
const ACTION_LABEL = { allow: "Whitelist", deny: "Blacklist" };

async function loadFilter(fresh) {
  if (df.loading) return df.loading;
  df.loading = (async () => {
    let st;
    try {
      st = await api("dnsfilter", fresh ? { fresh: 1 } : {});
    } catch (e) {
      if (e.status === 503) setFilterState(null);
      else if (activeTab === "filter") showDfBanner("DNS-Filter-Status nicht abrufbar: " + e.message);
      df.loading = null;
      return;
    }
    try {
      setFilterState(st);
    } catch (e) {  // Darstellungsfehler nicht als API-Fehler ausgeben
      console.error(e);
      showDfBanner("Darstellungsfehler im Dashboard (Seite neu laden): " + e.message);
    } finally { df.loading = null; }
  })();
  return df.loading;
}
function setFilterState(st) {
  df.state = st;
  if (st) df.offset = st.server_time - Date.now() / 1000;
  renderFilterIndicators();
  refreshMarks();
  if (activeTab === "filter") renderFilterTab();
  scheduleProgressPoll();
}
const dfCfg = () => (df.state && df.state.config) || null;
const dfPause = () => (df.state && df.state.pause) || null;
const dfWritable = () => !!(df.state && df.state.writable && df.state.available);
const serverNow = () => Date.now() / 1000 + df.offset;

function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(s).padStart(2, "0");
}

// --- Abgleich Domain <-> Ausnahmen (exakt, Wildcard, übergeordnete Domain)
function exMatch(qname) {
  const cfg = dfCfg();
  if (!cfg || !qname) return null;
  const byDomain = new Map(cfg.domains.map((d) => [String(d.domain).toLowerCase(), d]));
  const labels = qname.toLowerCase().split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const cand = labels.slice(i).join(".");
    if (byDomain.has(cand)) return { entry: byDomain.get(cand), exact: i === 0 };
    if (i > 0 && byDomain.has("*." + cand)) return { entry: byDomain.get("*." + cand), exact: false };
  }
  return null;
}
function markHtml(qname) {
  const m = exMatch(qname);
  if (!m) return "";
  const cls = m.entry.action === "allow" ? "allowed" : "blocked";
  const label = ACTION_LABEL[m.entry.action] || m.entry.action;
  const title = m.exact ? `Eintrag auf der ${label}` : `Übergeordneter Eintrag ${m.entry.domain} (${label}) – Wirkung auf Subdomains laut FRITZ!OS nicht verifiziert`;
  return `<span class="badge ${cls} list-badge" title="${esc(title)}">${m.exact ? "" : "≈ "}${esc(label)}</span>`;
}
function refreshMarks() {
  document.querySelectorAll("[data-mark]").forEach((el) => { el.innerHTML = markHtml(el.dataset.mark); });
}
function registrable(qname) {
  const l = qname.split(".");
  if (l.length <= 2) return null;
  const sld = ["co", "com", "org", "net", "gov", "ac", "edu"];
  const n = l[l.length - 1].length === 2 && sld.includes(l[l.length - 2]) ? 3 : 2;
  return l.length > n ? l.slice(-n).join(".") : null;
}

// --- Kopfzeile / Übersicht
function renderFilterIndicators() {
  const pill = $("dfPill"), cfg = dfCfg(), p = dfPause();
  if (!df.state) { pill.classList.add("hidden"); $("kFilterState").textContent = "–"; return; }
  pill.classList.remove("hidden");
  let cls, text, sub = "";
  if (!cfg) { cls = "error"; text = "Filter: ?"; sub = df.state.error || ""; }
  else if (p) { cls = "backoff"; text = "Filter pausiert"; sub = "noch " + fmtDur(p.resume_at - serverNow()); }
  else if (cfg.enabled) { cls = "running"; text = "Filter aktiv"; }
  else { cls = "auth_error"; text = "Filter AUS"; }
  pill.className = "pill link-pill " + cls;
  pill.innerHTML = esc(text) + (p ? ` <span class="df-countdown">${esc(fmtDur(p.resume_at - serverNow()))}</span>` : "");
  $("kFilterState").textContent = !cfg ? "?" : p ? "Pausiert" : cfg.enabled ? "Aktiv" : "Inaktiv";
  $("kFilterState").className = !cfg ? "" : p ? "warn" : cfg.enabled ? "ok" : "bad";
  $("kFilterSub").innerHTML = p ? `Reaktivierung in <span class="df-countdown">${esc(fmtDur(p.resume_at - serverNow()))}</span>` : esc(sub || (df.state.stale ? "veralteter Stand" : ""));
  if (cfg) {
    $("kFilterEntries").textContent = fmtN.format(cfg.filterlist_entries || 0);
    const wl = cfg.domains.filter((d) => d.action === "allow").length, bl = cfg.domains.length - wl;
    const errs = (df.state.filterlists_detail || []).filter((l) => l.health.state === "error").length;
    $("kFilterEx").textContent = `${wl} Whitelist · ${bl} Blacklist` + (errs ? ` · ${errs} Liste${errs > 1 ? "n" : ""} mit Fehler` : "");
  }
}
function tickCountdown() {
  const p = dfPause();
  if (!p) return;
  const rem = p.resume_at - serverNow();
  document.querySelectorAll(".df-countdown").forEach((el) => { el.textContent = fmtDur(rem); });
  if (rem <= 0 && !df.resumePoll) {  // fällig: Server reaktiviert -> Status nachladen
    df.resumePoll = setTimeout(async () => { df.resumePoll = null; await loadFilter(true); }, 4000);
  }
}

// --- Tab „DNS-Filter“
function showDfBanner(msg) {
  const b = $("dfBanner");
  if (msg) { b.textContent = msg; b.classList.remove("hidden"); } else b.classList.add("hidden");
}
function pauseButtons() {
  return [5, 15, 30, 60].map((m) => `<button class="btn ghost small" data-pause="${m}">${m < 60 ? m + " min" : "1 h"}</button>`).join("") +
    `<input type="number" min="1" max="1440" placeholder="min" class="pause-custom" aria-label="Eigene Dauer in Minuten">` +
    `<button class="btn ghost small" data-pause="custom">Pausieren</button>`;
}
function renderFilterTab() {
  const st = df.state;
  if (!st) { showDfBanner("DNS-Filterverwaltung nicht verfügbar – FRITZ!Box-Zugangsdaten konfiguriert?"); return; }
  const cfg = st.config, p = st.pause, w = dfWritable();
  const notes = [];
  if (st.error) notes.push((st.stale ? "Veralteter Stand – " : "") + "FRITZ!Box: " + st.error);
  if (!st.writable) notes.push("Nur-Lese-Modus: Schreibzugriff ist in der App-Konfiguration deaktiviert (dnsfilter_management).");
  showDfBanner(notes.join(" · "));
  document.querySelectorAll("[data-pause-group]").forEach((el) => { if (!el.dataset.ready) { el.innerHTML = pauseButtons(); el.dataset.ready = "1"; } });
  $("dfAddCard").classList.toggle("hidden", !w);
  if (!cfg) return;
  const badge = $("dfStateBadge");
  badge.className = "state-badge " + (p ? "warn" : cfg.enabled ? "ok" : "bad");
  badge.textContent = p ? "Pausiert" : cfg.enabled ? "Aktiv" : "Ausgeschaltet";
  $("dfStateSub").textContent = "Stand: " + (st.fetched_at ? fmtTime(st.fetched_at, true) : "–");
  const tg = $("dfToggle");
  tg.className = "btn " + (cfg.enabled ? "danger" : "") + (w && !p ? "" : " hidden");  // während Pause: eigener Button
  tg.textContent = cfg.enabled ? "Filter ausschalten …" : "Filter einschalten …";
  $("dfPauseBox").classList.toggle("hidden", !p);
  $("dfPauseStart").classList.toggle("hidden", !(w && !p && cfg.enabled));
  if (p) {
    $("dfResumeAt").textContent = `(um ${fmtTime(p.resume_at, false)})`;
    const err = $("dfResumeErr");
    if (p.last_error) {
      err.textContent = `Automatische Reaktivierung fehlgeschlagen (${p.attempts}×): ${p.last_error}` +
        (p.next_retry ? ` – nächster Versuch ${fmtTime(p.next_retry, false)}` : "");
      err.classList.remove("hidden");
    } else err.classList.add("hidden");
    $("dfResume").classList.toggle("hidden", !w);
  }
  const au = cfg.automaticUpdate || {};
  kv($("dfInfo"), [["Automatische Listen-Aktualisierung", fmtAuto(au)],
    ["Ausnahmen", `${cfg.domains.length} Einträge`], ["Filterlisten", `${cfg.filterlists.length} (${fmtN.format(cfg.filterlist_entries)} Einträge)`]]);
  // Statistik
  const q = (cfg.statistics || {}).dnsQueryCount || {};
  const tiles = [];
  if (Number.isFinite(q.total)) tiles.push(["Anfragen", fmtN.format(q.total)]);
  if (Number.isFinite(q.blocked)) tiles.push(["Blockiert", fmtN.format(q.blocked)]);
  if (Number.isFinite(q.total) && Number.isFinite(q.blocked)) tiles.push(["Rate", pct(q.total ? q.blocked / q.total * 100 : 0)]);
  $("dfStats").innerHTML = tiles.length ? tiles.map(([k, v]) => `<div class="kpi"><span>${k}</span><b>${v}</b></div>`).join("")
    : `<p class="muted">Keine Statistik geliefert.</p>`;
  const more = [];
  flatten(cfg.statistics || {}, "", more, ["dnsQueryCount.total", "dnsQueryCount.blocked"]);
  kv($("dfStatsMore"), more);
  renderLists();
  renderFilterlists();
}
function flatten(obj, prefix, out, skip = []) {
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === undefined) continue;
    const key = prefix ? prefix + "." + k : k;
    if (skip.includes(key)) continue;
    if (v && typeof v === "object" && !Array.isArray(v)) flatten(v, key, out, skip);
    else out.push([key, typeof v === "number" ? fmtN.format(v) : Array.isArray(v) ? v.join(", ") : String(v)]);
  }
}
function renderLists() {
  const cfg = dfCfg();
  if (!cfg) return;
  const q = $("dfSearch").value.trim().toLowerCase(), w = dfWritable();
  const rows = (action) => cfg.domains.filter((d) => d.action === action && (!q || d.domain.includes(q) || (d.comment || "").toLowerCase().includes(q)))
    .sort((a, b) => a.domain.localeCompare(b.domain));
  for (const [action, el, cnt] of [["allow", "dfWhitelist", "dfWlCount"], ["deny", "dfBlacklist", "dfBlCount"]]) {
    const r = rows(action);
    $(cnt).textContent = cfg.domains.filter((d) => d.action === action).length;
    $(el).innerHTML = r.length ? `<tr><th>Domain</th><th>Kommentar</th><th></th></tr>` + r.map((d) => `<tr>
      <td class="dom"><a data-domain="${esc(d.domain)}">${esc(d.domain)}</a>${d.enabled === false ? ' <span class="badge no_answer">inaktiv</span>' : ""}</td>
      <td class="ips">${esc(d.comment || "")}</td>
      <td class="act nowrap">${w ? `<button class="btn ghost small" data-edit="${esc(d.uid)}">Bearbeiten</button>
        <button class="btn ghost small danger-text" data-del="${esc(d.uid)}">Löschen</button>` : ""}</td></tr>`).join("")
      : `<tr><td class="muted">${q ? "Keine Treffer" : "Keine Einträge"}</td></tr>`;
  }
}

// --- Dialoge / Toast
function openDialog({ title, body, ok = "OK", danger = false, onOk }) {
  const m = $("modal");
  $("modalTitle").textContent = title;
  $("modalBody").innerHTML = body;
  $("modalErr").classList.add("hidden");
  const btn = $("modalOk");
  btn.textContent = ok;
  btn.className = "btn" + (danger ? " danger" : "");
  btn.disabled = false;
  m.classList.remove("hidden");
  const first = m.querySelector("input, select");
  (first || btn).focus();
  $("modalBox").onsubmit = async (ev) => {
    ev.preventDefault();
    btn.disabled = true;
    btn.textContent = "Wird gespeichert …";
    try {
      await onOk();
      closeDialog();
    } catch (e) {
      $("modalErr").textContent = e.message;
      $("modalErr").classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = ok;
    }
  };
}
function closeDialog() { $("modal").classList.add("hidden"); }
$("modalCancel").addEventListener("click", closeDialog);
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeDialog(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDialog(); hideMenu(); } });
let toastT;
function toast(msg, kind = "ok") {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast " + kind;
  clearTimeout(toastT);
  toastT = setTimeout(() => t.classList.add("hidden"), kind === "err" ? 8000 : 4500);
}

async function dfWrite(method, path, body, okMsg) {
  try {
    const st = await api("dnsfilter/" + path, {}, {
      method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
    });
    setFilterState(st);
    toast(okMsg);
    return st;
  } catch (e) {
    loadFilter(true);
    throw e;
  }
}

function entryForm(d) {
  return `<label class="field">Domain<input name="domain" type="text" required maxlength="253" value="${esc(d.domain || "")}" autocomplete="off"></label>
    <label class="field">Aktion<select name="action">
      <option value="allow" ${d.action === "allow" ? "selected" : ""}>Whitelist – erlauben</option>
      <option value="deny" ${d.action === "deny" ? "selected" : ""}>Blacklist – sperren</option></select></label>
    <label class="field">Kommentar<input name="comment" type="text" maxlength="200" value="${esc(d.comment || "")}"></label>
    <p class="muted small-text">Wird direkt in der FRITZ!Box gespeichert und danach erneut ausgelesen. Geräte können
      zwischengespeicherte DNS-Antworten noch kurz weiterverwenden.</p>`;
}
const formVal = (n) => $("modalBody").querySelector(`[name=${n}]`).value;

function dlgAdd(domain, action, comment = "") {
  openDialog({
    title: "Ausnahme hinzufügen", body: entryForm({ domain, action, comment }), ok: "Hinzufügen",
    onOk: () => dfWrite("POST", "domains", { domain: formVal("domain"), action: formVal("action"), comment: formVal("comment") },
      `${formVal("domain")} zur ${ACTION_LABEL[formVal("action")]} hinzugefügt`),
  });
}
function dlgEdit(entry, preset = {}) {
  openDialog({
    title: "Eintrag bearbeiten", body: entryForm({ ...entry, ...preset }), ok: "Speichern",
    onOk: () => dfWrite("PUT", "domains/" + encodeURIComponent(entry.uid),
      { domain: formVal("domain"), action: formVal("action"), comment: formVal("comment") }, `${formVal("domain")} gespeichert`),
  });
}
function dlgDelete(entry) {
  openDialog({
    title: "Eintrag löschen?", danger: true, ok: "Löschen",
    body: `<p><b>${esc(entry.domain)}</b> wird von der ${ACTION_LABEL[entry.action]} der FRITZ!Box entfernt.</p>`,
    onOk: () => dfWrite("DELETE", "domains/" + encodeURIComponent(entry.uid), null, `${entry.domain} entfernt`),
  });
}
function dlgToggle() {
  const cfg = dfCfg(), p = dfPause();
  if (!cfg) return;
  if (!cfg.enabled) {
    return openDialog({ title: "DNS-Filter einschalten?", ok: "Einschalten",
      body: `<p>Der DNS-Filter der FRITZ!Box wird wieder aktiviert${p ? " und die laufende Pause beendet" : ""}.</p>`,
      onOk: () => dfWrite("PUT", "enabled", { enabled: true }, "DNS-Filter eingeschaltet") });
  }
  openDialog({ title: "DNS-Filter dauerhaft ausschalten?", danger: true, ok: "Dauerhaft ausschalten",
    body: `<p>Der DNS-Filter bleibt aus, bis du ihn wieder einschaltest. Für eine befristete Pause besser „Pausieren“ verwenden.</p>
      <p class="muted small-text">Die Einstellung der automatischen Listen-Aktualisierung bleibt unverändert.</p>`,
    onOk: () => dfWrite("PUT", "enabled", { enabled: false }, "DNS-Filter ausgeschaltet") });
}
function dlgPause(minutes) {
  if (!(minutes >= 1 && minutes <= 1440)) return toast("Dauer muss zwischen 1 und 1440 Minuten liegen", "err");
  const p = dfPause();
  openDialog({ title: p ? "Pause ändern?" : `DNS-Filter ${minutes} min pausieren?`, ok: p ? "Pause neu setzen" : "Pausieren",
    body: `<p>Der DNS-Filter wird ${p ? "weiterhin" : ""} ausgeschaltet und um <b>${esc(fmtTime(serverNow() + minutes * 60, false))}</b>
      automatisch wieder eingeschaltet – auch nach einem Neustart der App.</p>`,
    onOk: () => dfWrite("POST", "pause", { minutes }, `DNS-Filter für ${minutes} min pausiert`) });
}
function dlgResume() {
  openDialog({ title: "DNS-Filter jetzt wieder einschalten?", ok: "Einschalten", body: "<p>Die Pause wird vorzeitig beendet.</p>",
    onOk: () => dfWrite("POST", "resume", null, "DNS-Filter wieder eingeschaltet") });
}

// --- Kontextmenü im Live-Protokoll / Auswertungen
function hideMenu() { $("ctxMenu").classList.add("hidden"); }
function showMenu(qname, status, x, y) {
  const m = $("ctxMenu"), w = dfWritable(), hit = exMatch(qname), items = [];
  items.push(`<div class="ctx-head">${esc(qname)}</div>`);
  if (!df.state || !df.state.available) items.push(`<div class="ctx-note">DNS-Filter nicht erreichbar${df.state && df.state.error ? ": " + esc(df.state.error) : ""}</div>`);
  else if (!w) items.push(`<div class="ctx-note">Nur-Lese-Modus</div>`);
  if (hit) {
    const lab = ACTION_LABEL[hit.entry.action];
    items.push(`<div class="ctx-note">${hit.exact ? "Steht auf der " + lab : `Übergeordneter Eintrag: ${esc(hit.entry.domain)} (${lab})`}</div>`);
    if (w) {
      const other = hit.entry.action === "allow" ? "deny" : "allow";
      items.push(`<button data-c="edit">Eintrag ${hit.exact ? "" : esc(hit.entry.domain) + " "}bearbeiten …</button>`);
      items.push(`<button data-c="move" data-a="${other}">In ${ACTION_LABEL[other]} verschieben …</button>`);
      items.push(`<button data-c="del" class="danger-text">Eintrag entfernen …</button>`);
    }
  }
  if (w && !(hit && hit.exact)) {
    const order = status === "blocked" ? ["allow", "deny"] : ["deny", "allow"];
    for (const a of order) items.push(`<button data-c="add" data-a="${a}" data-d="${esc(qname)}">${a === "allow" ? "Erlauben (Whitelist)" : "Sperren (Blacklist)"} …</button>`);
    const reg = registrable(qname);
    if (reg && !(hit && hit.entry.domain === reg)) {
      items.push(`<button data-c="add" data-a="${order[0]}" data-d="${esc(reg)}">Ganze Domain ${esc(reg)} ${order[0] === "allow" ? "erlauben" : "sperren"} …</button>`);
    }
  }
  items.push(`<button data-c="analyse">Auswertung zu dieser Domain</button>`);
  m.innerHTML = items.join("");
  m.dataset.q = qname;
  m.classList.remove("hidden");
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(8, Math.min(x, window.innerWidth - r.width - 8)) + "px";
  m.style.top = Math.max(8, Math.min(y, window.innerHeight - r.height - 8)) + "px";
  m.onclick = (ev) => {
    const b = ev.target.closest("button[data-c]");
    if (!b) return;
    hideMenu();
    const c = b.dataset.c;
    if (c === "add") dlgAdd(b.dataset.d, b.dataset.a, "FritzHole: aus Live-Protokoll");
    else if (c === "edit") dlgEdit(hit.entry);
    else if (c === "move") dlgEdit(hit.entry, { action: b.dataset.a });
    else if (c === "del") dlgDelete(hit.entry);
    else if (c === "analyse") { an.q = qname; $("anSearch").value = qname; showTab("analysis"); }
  };
}
document.addEventListener("click", async (ev) => {
  const menuBtn = ev.target.closest("button[data-menu]");
  if (menuBtn) {
    ev.stopPropagation();
    if (!df.state || Date.now() / 1000 + df.offset - (df.state.fetched_at || 0) > 60) loadFilter(false).then(refreshMarks);
    const r = menuBtn.getBoundingClientRect();
    return showMenu(menuBtn.dataset.menu, menuBtn.dataset.st, r.right - 240, r.bottom + 4);
  }
  if (!ev.target.closest("#ctxMenu")) hideMenu();
  const g = ev.target.closest("[data-goto]");
  if (g) return showTab(g.dataset.goto);
  const ed = ev.target.closest("button[data-edit]"), del = ev.target.closest("button[data-del]");
  const byUid = (uid) => (dfCfg() || { domains: [] }).domains.find((d) => d.uid === uid);
  if (ed && byUid(ed.dataset.edit)) return dlgEdit(byUid(ed.dataset.edit));
  if (del && byUid(del.dataset.del)) return dlgDelete(byUid(del.dataset.del));
  const pb = ev.target.closest("button[data-pause]");
  if (pb) {
    const v = pb.dataset.pause === "custom" ? Number(pb.parentElement.querySelector(".pause-custom").value) : Number(pb.dataset.pause);
    return dlgPause(v);
  }
}, true);
document.addEventListener("contextmenu", (ev) => {
  const tr = ev.target.closest("table.events tr");
  const btn = tr && tr.querySelector("button[data-menu]");
  if (!btn) return;
  ev.preventDefault();
  showMenu(btn.dataset.menu, btn.dataset.st, ev.clientX, ev.clientY);
});
window.addEventListener("scroll", hideMenu);  // nur Seiten-Scroll, nicht Tabellen-Scroll
$("dfPill").addEventListener("click", () => showTab("filter"));
$("dfToggle").addEventListener("click", dlgToggle);
$("dfResume").addEventListener("click", dlgResume);
$("dfReload").addEventListener("click", () => loadFilter(true));
$("dfSearch").addEventListener("input", renderLists);
$("dfAddForm").addEventListener("submit", (ev) => {
  ev.preventDefault();
  dlgAdd($("dfAddDomain").value.trim(), $("dfAddAction").value, $("dfAddComment").value);
});

// ------------------------------------------------------------------ Filterlisten
const FL_STATE = {
  ready: ["allowed", "Bereit"], error: ["blocked", "Fehler"], updating: ["nxdomain", "Aktualisierung läuft"],
  not_ready: ["nxdomain", "Nicht bereit"], disabled: ["no_answer", "Deaktiviert"], unknown: ["no_answer", "Status unbekannt"],
};
const CAUSE = { manual: "manuell", automatic: "automatisch", auto: "automatisch" };
// Stufen exakt wie in der FRITZ!Box-Oberfläche
const AUTO_PRESETS = [["8h", "Alle 8 Stunden"], ["daily", "Täglich"], ["weekly", "Wöchentlich"], ["monthly", "Monatlich"], ["never", "Nie"]];
const AUTO_LABEL = Object.fromEntries(AUTO_PRESETS);
function fmtAuto(au, preset) {
  if (preset === undefined) preset = df.state && df.state.auto_preset;
  if (preset) return AUTO_LABEL[preset];
  if (!au || au.enabled === undefined) return "–";
  // Wert entspricht keiner FRITZ!Box-Stufe (z. B. per API gesetzt) -> roh anzeigen
  return `${au.enabled ? "an" : "aus"}, Intervall ${au.interval} s (keine FRITZ!Box-Stufe)`;
}
const fmtTs = (t) => (t ? fmtTime(t, true) : "–");

function renderFilterlists() {
  const st = df.state, cfg = dfCfg(), w = dfWritable();
  if (!st || !cfg) return;
  const lists = st.filterlists_detail || [];
  $("flAdd").classList.toggle("hidden", !w);
  $("flUpdate").classList.toggle("hidden", !w);
  const au = cfg.automaticUpdate || {};
  $("flAuto").innerHTML = `<span class="muted">Automatische Aktualisierung:</span>
    <span class="badge ${au.enabled ? "allowed" : "no_answer"}">${esc(fmtAuto(au, st.auto_preset))}</span>
    ${st.manual_last ? `<span class="muted">· letzte manuelle Anforderung ${esc(fmtTs(st.manual_last))}</span>` : ""}
    ${w ? `<button class="btn ghost small" id="flAutoEdit">Ändern …</button>` : ""}`;
  renderProgress();
  $("flList").innerHTML = lists.length ? lists.map((l) => {
    const h = l.health, [cls, label] = FL_STATE[h.state] || FL_STATE.unknown;
    const meta = [
      `<b>${h.entry_count != null ? fmtN.format(h.entry_count) : "–"}</b> Einträge`,
      `zuletzt erfolgreich: ${esc(fmtTs(h.last_success))}`,
    ];
    if (h.latest_ts || h.latest_status) {
      meta.push(`letzter Versuch: ${esc(fmtTs(h.latest_ts))}${h.latest_status ? ` (${esc(h.latest_status)}` + (h.cause ? `, ${esc(CAUSE[h.cause] || h.cause)}` : "") + ")" : ""}`);
    }
    const err = h.state === "error" || h.error_code != null
      ? `<div class="fl-err">Fehler${h.error_code != null ? " " + esc(h.error_code) : ""}${h.error_message ? ": " + esc(h.error_message) : ""}
         ${h.is_ready === false ? " – Liste ist nicht einsatzbereit" : ""}${h.entry_count === 0 ? ", 0 Einträge" : ""}</div>` : "";
    return `<div class="fl-item ${esc(h.state)}">
      <div class="fl-top">
        <div class="fl-name">${esc(l.name ?? "?")} <span class="badge ${cls}">${label}</span></div>
        ${w ? `<button class="switch ${l.enabled ? "on" : ""}" data-fl-toggle="${esc(l.uid)}" role="switch" aria-checked="${!!l.enabled}"
             title="${l.enabled ? "Liste deaktivieren" : "Liste aktivieren"}"><span></span></button>` : ""}
      </div>
      <div class="fl-url">${esc(l.url ?? "")}</div>
      <div class="fl-meta">${meta.join(" · ")}</div>
      ${err}
      ${w ? `<div class="fl-actions"><button class="btn ghost small" data-fl-edit="${esc(l.uid)}">Bearbeiten</button>
        <button class="btn ghost small danger-text" data-fl-del="${esc(l.uid)}">Löschen</button></div>` : ""}
    </div>`;
  }).join("") : `<p class="muted">Keine Filterlisten konfiguriert.</p>`;
}

// --- Fortschritt manuelle Aktualisierung (nur bestätigte Zustände der FRITZ!Box)
const fl = { pollT: null, pollN: 0, dismissed: null };
function renderProgress() {
  const box = $("flProgress"), p = df.state && df.state.manual_update;
  if (!p || fl.dismissed === p.requested_at) { box.classList.add("hidden"); return; }
  const done = p.lists.filter((x) => x.state === "done" || x.state === "error").length;
  const failed = p.lists.filter((x) => x.state === "error").map((x) => x.name);
  const unk = p.lists.filter((x) => x.state === "unknown").map((x) => `${x.name} (${x.status})`);
  const txt = {
    requested: ["warn", "Aktualisierung angefordert – warte auf Rückmeldung der FRITZ!Box …"],
    running: ["warn", `Aktualisierung läuft – ${done} von ${p.lists.length} aktiven Listen gemeldet`],
    success: ["ok", "Alle aktiven Filterlisten wurden laut FRITZ!Box erfolgreich aktualisiert."],
    error: ["bad", `Aktualisierung abgeschlossen – Fehler bei: ${failed.join(", ")}`],
    unknown: ["warn", `Aktualisierung gemeldet, Status nicht eindeutig: ${unk.join(", ")}`],
    timeout: ["bad", "Keine vollständige Rückmeldung nach 10 Minuten – bitte Status der einzelnen Listen prüfen."],
  }[p.phase] || ["warn", p.phase];
  box.className = "progress " + txt[0];
  box.innerHTML = `<span>${esc(txt[1])}</span><span class="muted small-text">angefordert ${esc(fmtTime(p.requested_at, false))}</span>
    ${p.finished ? `<button class="icon-btn" id="flProgClose" aria-label="Schließen">×</button>` : `<span class="spinner" aria-hidden="true"></span>`}`;
}
function scheduleProgressPoll() {
  const p = df.state && df.state.manual_update;
  clearTimeout(fl.pollT);
  if (!p || p.finished) { fl.pollN = 0; return; }
  // Begrenztes Nachfragen mit wachsendem Abstand, nur solange der Tab offen ist
  const delays = [5, 5, 10, 10, 15, 20, 30, 30, 45, 60];
  const d = delays[Math.min(fl.pollN, delays.length - 1)] * 1000;
  fl.pollN++;
  fl.pollT = setTimeout(() => { if (activeTab === "filter" && !document.hidden) loadFilter(true); else scheduleProgressPoll(); }, d);
}

// --- Dialoge
function listForm(l) {
  return `<label class="field">Name<input name="name" type="text" required maxlength="100" value="${esc(l.name || "")}"></label>
    <label class="field">URL (HTTPS)<input name="url" type="url" required maxlength="1024" value="${esc(l.url || "")}" placeholder="https://…" autocomplete="off"></label>
    <label class="check"><input name="enabled" type="checkbox" ${l.enabled !== false ? "checked" : ""}> Liste aktiv</label>
    <p class="muted small-text">Wird direkt in der FRITZ!Box gespeichert und danach erneut ausgelesen. Die Einträge lädt
      die FRITZ!Box erst beim nächsten Update der Liste.</p>`;
}
const listById = (uid) => ((df.state && df.state.filterlists_detail) || []).find((l) => l.uid === uid);
const formChecked = (n) => $("modalBody").querySelector(`[name=${n}]`).checked;

function dlgListAdd() {
  openDialog({ title: "Filterliste hinzufügen", body: listForm({ enabled: true }), ok: "Hinzufügen",
    onOk: () => dfWrite("POST", "filterlists", { name: formVal("name"), url: formVal("url"), enabled: formChecked("enabled") },
      `Filterliste „${formVal("name")}“ hinzugefügt`) });
}
function dlgListEdit(l) {
  openDialog({ title: "Filterliste bearbeiten", body: listForm(l), ok: "Speichern",
    onOk: () => dfWrite("PUT", "filterlists/" + encodeURIComponent(l.uid),
      { name: formVal("name"), url: formVal("url"), enabled: formChecked("enabled") }, `„${formVal("name")}“ gespeichert`) });
}
function dlgListToggle(l) {
  const on = !l.enabled;
  openDialog({ title: `Filterliste ${on ? "aktivieren" : "deaktivieren"}?`, ok: on ? "Aktivieren" : "Deaktivieren", danger: !on,
    body: `<p><b>${esc(l.name)}</b> wird ${on ? "aktiviert" : "deaktiviert"}.${on ? "" : " Die Domains dieser Liste werden dann nicht mehr blockiert."}</p>`,
    onOk: () => dfWrite("PUT", "filterlists/" + encodeURIComponent(l.uid), { enabled: on }, `„${l.name}“ ${on ? "aktiviert" : "deaktiviert"}`) });
}
function dlgListDelete(l) {
  openDialog({ title: "Filterliste löschen?", danger: true, ok: "Endgültig löschen",
    body: `<p><b>${esc(l.name)}</b><br><span class="ips">${esc(l.url)}</span></p>
      <p>Die Liste wird aus der FRITZ!Box entfernt. Das lässt sich nur durch erneutes Hinzufügen rückgängig machen.</p>`,
    onOk: () => dfWrite("DELETE", "filterlists/" + encodeURIComponent(l.uid), null, `„${l.name}“ gelöscht`) });
}
function dlgUpdateAll() {
  const n = ((df.state && df.state.filterlists_detail) || []).filter((l) => l.enabled !== false).length;
  openDialog({ title: "Alle Filterlisten jetzt aktualisieren?", ok: "Aktualisierung anfordern",
    body: `<p>Die FRITZ!Box lädt ${n} aktive Liste${n === 1 ? "" : "n"} neu herunter. Der Fortschritt wird angezeigt, sobald
      die FRITZ!Box ihn meldet.</p>`,
    onOk: async () => {
      fl.pollN = 0; fl.dismissed = null;
      await dfWrite("POST", "update", null, "Aktualisierung angefordert – noch nicht abgeschlossen");
    } });
}
function dlgAuto() {
  const cur = df.state && df.state.auto_preset;
  const au = (dfCfg() || {}).automaticUpdate || {};
  const opts = (cur ? "" : `<option value="" selected disabled>Aktuell: ${esc(fmtAuto(au, null))}</option>`) +
    AUTO_PRESETS.map(([k, label]) => `<option value="${k}" ${k === cur ? "selected" : ""}>${esc(label)}</option>`).join("");
  openDialog({ title: "Automatische Aktualisierung", ok: "Speichern",
    body: `<label class="field">Filterlisten aktualisieren<select name="preset">${opts}</select></label>
      <p class="muted small-text">Gleiche Stufen wie in der FRITZ!Box-Oberfläche. Der Hauptschalter des DNS-Filters
        (und eine laufende Pause) bleibt unverändert.</p>`,
    onOk: async () => {
      const preset = formVal("preset");
      if (!preset) throw new Error("Bitte eine Stufe auswählen");
      if (preset === cur) return;
      await dfWrite("PUT", "auto-update", { preset }, `Automatische Aktualisierung: ${AUTO_LABEL[preset]}`);
    } });
}
document.addEventListener("click", (ev) => {
  const t = ev.target.closest("[data-fl-toggle],[data-fl-edit],[data-fl-del],#flAdd,#flUpdate,#flAutoEdit,#flProgClose,#flJump");
  if (!t) return;
  if (t.id === "flAdd") return dlgListAdd();
  if (t.id === "flUpdate") return dlgUpdateAll();
  if (t.id === "flAutoEdit") return dlgAuto();
  if (t.id === "flJump") return $("flCard").scrollIntoView({ behavior: "smooth" });
  if (t.id === "flProgClose") { fl.dismissed = df.state.manual_update.requested_at; return renderProgress(); }
  const l = listById(t.dataset.flToggle || t.dataset.flEdit || t.dataset.flDel);
  if (!l) return;
  if (t.dataset.flToggle) dlgListToggle(l);
  else if (t.dataset.flEdit) dlgListEdit(l);
  else dlgListDelete(l);
});

// ------------------------------------------------------------------ init
function statusOptions() {
  const opts = `<option value="">Alle Status</option>` + Object.entries(STATUS).map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
  document.querySelectorAll(".statusSel").forEach((s) => (s.innerHTML = opts));
}
async function refresh() {
  try {
    if (activeTab === "overview") await loadOverview();
    else if (activeTab === "live") await loadLive();
    else if (activeTab === "analysis") await loadAnalysis();
    else if (activeTab === "devices") await loadDevices();
    else if (activeTab === "filter") await loadFilter(true);
    await loadStatus();
  } catch (e) { console.error(e); }
}
$("range").addEventListener("change", refresh);
let resizeDeb;
window.addEventListener("resize", () => { clearTimeout(resizeDeb); resizeDeb = setTimeout(() => { if (activeTab === "overview") loadOverview(); }, 300); });

statusOptions();
loadDevices().then(refresh);
loadFilter(false);
setInterval(() => loadFilter(false), 60000);
setInterval(tickCountdown, 1000);
connectStream();
setInterval(() => { if (activeTab === "overview" || activeTab === "status") refresh(); else loadStatus(); }, 15000);
setInterval(loadDevices, 60000);
