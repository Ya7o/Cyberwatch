/* Cyberwatch P3 — Intelligence analytique déterministe, sans dépendance. */
(() => {
  "use strict";
  const DAY = 864e5;
  const UNKNOWN = "Inconnu";
  const dims = ["threat", "sector", "location"];
  const $ = (s) => document.querySelector(s);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const known = (v) => Boolean(String(v || "").trim()) && String(v).trim() !== UNKNOWN;
  const sources = (row) => Array.isArray(row.sources) ? new Set(row.sources).size : 0;
  const dateOf = (row) => { const d = new Date(row.date); return Number.isNaN(d.getTime()) ? null : d; };
  const slice = (rows, end, days, offset = 0) => {
    const hi = new Date(end.getTime() - offset * DAY + DAY - 1);
    const lo = new Date(end.getTime() - (offset + days - 1) * DAY);
    return rows.filter((row) => { const d = dateOf(row); return d && d >= lo && d <= hi; });
  };
  const pct = (cur, prev) => prev === 0 ? (cur ? 100 : 0) : Math.round(1000 * (cur - prev) / prev) / 10;
  const count = (rows, key) => {
    const map = new Map();
    rows.forEach((row) => { if (known(row[key])) map.set(row[key], (map.get(row[key]) || 0) + 1); });
    return map;
  };
  const confidence = (evidence) => {
    const n = evidence.length;
    const sample = Math.min(1, n / 12);
    const multi = n ? evidence.filter((r) => sources(r) > 1).length / n : 0;
    const complete = n ? evidence.reduce((sum, r) => sum + dims.filter((k) => known(r[k])).length, 0) / (n * dims.length) : 0;
    const score = Math.round(100 * (.55 * sample + .25 * multi + .20 * complete));
    return { score, level: score >= 75 ? "élevée" : score >= 50 ? "moyenne" : "faible" };
  };

  function signals(rows, anchor) {
    const out = [];
    [30, 90].forEach((days) => {
      const cur = slice(rows, anchor, days), prev = slice(rows, anchor, days, days);
      dims.forEach((dimension) => {
        const a = count(cur, dimension), b = count(prev, dimension);
        new Set([...a.keys(), ...b.keys()]).forEach((label) => {
          const now = a.get(label) || 0, before = b.get(label) || 0, delta = now - before;
          if (now < 3 || delta < 2 || (before > 0 && pct(now, before) < 50)) return;
          const evidence = cur.filter((r) => r[dimension] === label);
          out.push({ kind: before === 0 ? "Émergence" : "Accélération", dimension, label, days, now, before, delta, confidence: confidence(evidence), evidence });
        });
      });
      const beforePairs = new Set(prev.filter((r) => known(r.threat) && known(r.sector)).map((r) => `${r.threat}\u0000${r.sector}`));
      const pairMap = new Map();
      cur.forEach((r) => { if (known(r.threat) && known(r.sector)) { const k = `${r.threat}\u0000${r.sector}`; if (!pairMap.has(k)) pairMap.set(k, []); pairMap.get(k).push(r); } });
      pairMap.forEach((evidence, key) => {
        if (beforePairs.has(key) || evidence.length < 3) return;
        const [threat, sector] = key.split("\u0000");
        out.push({ kind: "Nouveau couple", dimension: "threat_sector", label: `${threat} × ${sector}`, days, now: evidence.length, before: 0, delta: evidence.length, confidence: confidence(evidence), evidence });
      });
    });
    const seen = new Set();
    return out.sort((a,b) => b.confidence.score - a.confidence.score || b.delta - a.delta || a.days - b.days)
      .filter((s) => { const k = `${s.kind}|${s.dimension}|${s.label}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 12);
  }

  function top(rows, key, n = 5) {
    return [...count(rows, key)].sort((a,b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]), "fr")).slice(0,n);
  }

  function injectShell() {
    const reliability = $("#fiabilite");
    if (!reliability || $("#p3-intelligence")) return false;
    const section = document.createElement("section");
    section.id = "p3-intelligence";
    section.className = "p3 card";
    section.innerHTML = `
      <div class="p3-head"><div><p class="p3-eyebrow">Intelligence</p><h2>Ce qui change</h2><p class="muted">Signaux calculés sur les publications observées, jamais assimilés à la prévalence réelle des cyberattaques.</p></div><div class="p3-tabs" role="group" aria-label="Fenêtre analytique"><button data-window="30" aria-pressed="true">30 j</button><button data-window="90" aria-pressed="false">90 j</button><button data-window="365" aria-pressed="false">365 j</button></div></div>
      <div id="p3-summary" class="p3-summary"></div>
      <div class="p3-grid"><div><h3>Signaux</h3><div id="p3-signals" class="p3-signals"></div></div><div><h3>Contexte de la fenêtre</h3><div id="p3-context" class="p3-context"></div></div></div>
      <details class="p3-method"><summary>Comment lire ces signaux</summary><p>Un signal exige au moins 3 incidents et +2 d'écart ; une accélération exige au moins +50 %. Les petits échantillons sont volontairement écartés. La confiance combine volume, corroboration multi-source et complétude des champs.</p></details>`;
    reliability.parentNode.insertBefore(section, reliability);
    return true;
  }

  let rows = [], anchor = new Date(), windowDays = 30, allSignals = [];
  function render() {
    const cur = slice(rows, anchor, windowDays), prev = slice(rows, anchor, windowDays, windowDays);
    const delta = cur.length - prev.length;
    const multi = cur.filter((r) => sources(r) > 1).length;
    const recurring = [...new Map(cur.map((r) => [r.org, 0]))].filter(([org]) => known(org)).map(([org]) => [org, cur.filter((r) => r.org === org).length]).filter(([,n]) => n >= 2).sort((a,b) => b[1]-a[1]).slice(0,5);
    $("#p3-summary").innerHTML = `<article><strong>${cur.length}</strong><span>incidents / ${windowDays} j</span></article><article><strong>${delta >= 0 ? "+" : ""}${delta}</strong><span>vs période précédente</span></article><article><strong>${cur.length ? Math.round(100*multi/cur.length) : 0}%</strong><span>multi-source</span></article><article><strong>${allSignals.filter((s) => s.days <= windowDays).length}</strong><span>signaux étayés</span></article>`;
    const visibleSignals = allSignals.filter((s) => s.days <= Math.max(30, windowDays)).slice(0,8);
    $("#p3-signals").innerHTML = visibleSignals.length ? visibleSignals.map((s) => `<button class="p3-signal" type="button" data-ids="${esc(s.evidence.map((r) => r.id).filter(Boolean).join(","))}"><span class="p3-kind">${esc(s.kind)} · ${s.days} j</span><strong>${esc(s.label)}</strong><span>${s.now} incidents vs ${s.before} · Δ +${s.delta}</span><span class="p3-confidence" data-level="${s.confidence.level}">Confiance ${s.confidence.level} · ${s.confidence.score}/100</span></button>`).join("") : `<p class="p3-empty">Aucun signal ne dépasse les seuils conservateurs sur cette période.</p>`;
    const threats = top(cur,"threat"), sectors = top(cur,"sector"), locations = top(cur,"location");
    const list = (title,data) => `<div><h4>${title}</h4>${data.length ? `<ol>${data.map(([k,n]) => `<li><span>${esc(k)}</span><strong>${n}</strong></li>`).join("")}</ol>` : `<p class="muted">Données insuffisantes</p>`}</div>`;
    $("#p3-context").innerHTML = list("Menaces", threats) + list("Secteurs", sectors) + list("Territoires", locations) + list("Organisations récurrentes", recurring);
  }

  /* La section n'est injectée qu'une fois les données confirmées : une
     Intelligence vide se lirait comme « aucun signal », alors qu'il s'agit
     d'une absence de données. */
  function abort(error) {
    console.error("P3 intelligence indisponible", error);
    $("#p3-intelligence")?.remove();
  }

  async function init() {
    try {
      const response = await fetch("assets/data/incidents.json", {cache:"no-cache"});
      if (!response.ok) return abort(new Error(String(response.status)));
      rows = await response.json();
      if (!Array.isArray(rows)) return abort(new Error("payload non conforme"));
      if (!injectShell()) return;
      const dates = rows.map(dateOf).filter(Boolean).sort((a,b)=>b-a);
      anchor = dates[0] || new Date();
      allSignals = signals(rows, anchor);
      $("#p3-intelligence").addEventListener("click", (event) => {
        const tab = event.target.closest("[data-window]");
        if (tab) {
          windowDays = Number(tab.dataset.window) || 30;
          document.querySelectorAll(".p3-tabs button").forEach((b) => b.setAttribute("aria-pressed", String(b === tab)));
          render(); return;
        }
        const signal = event.target.closest(".p3-signal");
        if (signal) {
          const ids = signal.dataset.ids.split(",").filter(Boolean);
          const first = ids[0];
          if (!first) return;
          const details = document.getElementById(`incident-details-${first.replace(/[^a-zA-Z0-9_-]/g,"-")}`);
          if (details) { details.hidden = false; details.scrollIntoView({behavior:"smooth",block:"center"}); }
        }
      });
      render();
    } catch (error) { abort(error); }
  }
  document.addEventListener("DOMContentLoaded", init);
})();
