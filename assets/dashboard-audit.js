/* Cyberwatch — correctifs d'audit UI appliqués au dashboard historique. */
(() => {
  "use strict";

  const state = {
    incidents: [],
    status: null,
    page: 1,
    pageSize: 50,
    sourceSearch: "",
    sourceStatus: "",
  };
  let tableObserver = null;
  let timer = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));

  function safeUrl(value) {
    if (!value) return "";
    try {
      const url = new URL(value, location.href);
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) { return ""; }
  }

  function host(value) {
    const url = safeUrl(value);
    if (!url) return "lien";
    try { return new URL(url).hostname.replace(/^www\./, ""); }
    catch (_) { return "lien"; }
  }

  function sourceLabel(id) {
    const labels = {
      BONJOURLAFUITE: "BonjourLaFuite",
      FRENCHBREACHES: "FrenchBreaches",
      CYBERATTAQUE_ORG: "Cyberattaque.org",
      RANSOMWARE_LIVE: "Ransomware.live",
      CERT_MU_ALERTS: "CERT-MU",
      KWEZI_NUMERIQUE: "Kwezi",
    };
    if (labels[id]) return labels[id];
    return String(id || "Source").toLowerCase().split("_")
      .map((p) => p ? p[0].toUpperCase() + p.slice(1) : "").join(" ");
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(0, 10);
    return date.toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
  }

  function installCss() {
    if ($("#dashboard-audit-css")) return;
    const style = document.createElement("style");
    style.id = "dashboard-audit-css";
    style.textContent = `
      #bonjour-v0{display:none!important}
      .incidents-card .table-scroll{max-height:none}
      .audit-toolbar,.audit-pager{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
      .audit-toolbar{margin:10px 0 12px}
      .audit-toolbar input,.audit-toolbar select,.audit-pager button,.audit-pager select{font:inherit;font-size:13px;padding:6px 9px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-primary)}
      .audit-toolbar input{flex:1;min-width:210px}.audit-count,.audit-pager{font-size:12.5px;color:var(--text-secondary)}
      .audit-pager{justify-content:space-between;margin-top:12px}.audit-pager-actions{display:flex;gap:8px;align-items:center}.audit-pager button:disabled{opacity:.45}
      .source-name{font-weight:650}.source-meta,.source-control{font-size:11.5px;color:var(--text-secondary)}
      .source-badges{display:flex;gap:5px;flex-wrap:wrap}.source-badge{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;background:var(--plane);font-size:11.5px;text-decoration:none;color:var(--text-secondary)}
      .source-badge:hover{color:var(--text-primary)}.evidence-links{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:11.5px;color:var(--text-secondary)}
      #sources-table{table-layout:auto!important}#sources-table td,#sources-table th{width:auto!important;vertical-align:top}.source-measures{white-space:normal!important}
      @media(max-width:700px){
        .topbar-inner{align-items:flex-start}.brand-sub{max-width:190px}.run-pill{white-space:normal;text-align:left}
        .filters{display:grid;grid-template-columns:1fr 1fr}.filter,.filter-grow{min-width:0}.filter-grow{grid-column:1/-1}.btn-reset{grid-column:1/-1}
        .incidents-card .table-scroll,.reliability .table-scroll{overflow:visible;max-height:none}
        #incidents-table thead,#sources-table thead{display:none}
        #incidents-table,#incidents-table tbody,#incidents-table tr,#incidents-table td,#sources-table,#sources-table tbody,#sources-table tr,#sources-table td{display:block;width:100%}
        #incidents-table tr,#sources-table tr{padding:11px 0;border-bottom:1px solid var(--grid)}
        #incidents-table td,#sources-table td{border:0!important;padding:3px 0!important;white-space:normal!important;max-width:none!important;overflow:visible!important;width:auto!important}
        #incidents-table td[data-label]::before,#sources-table td[data-label]::before{content:attr(data-label);display:inline-block;min-width:88px;margin-right:8px;color:var(--text-muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;vertical-align:top}
        #incidents-table .org-cell{font-size:16px;font-weight:650;padding-bottom:7px!important}#incidents-table .org-cell::before{display:none}
        #incidents-table .sources-cell::before{display:block;margin-bottom:4px}.audit-toolbar{align-items:stretch}.audit-toolbar input,.audit-toolbar select{width:100%;min-width:0}
        .audit-pager{align-items:flex-start}.audit-pager-actions{width:100%;justify-content:space-between}
      }
    `;
    document.head.appendChild(style);
  }

  function restructure() {
    installCss();
    const reliability = $("#fiabilite");
    const filters = $(".filters");
    if (reliability && filters) filters.parentNode.insertBefore(reliability, filters);
    if ($(".reliability-title")) $(".reliability-title").textContent = "Sources & fiabilité";
    const incidentCard = $("#incidents-table")?.closest("section.card");
    if (incidentCard) incidentCard.classList.add("incidents-card");

    const multi = $("#kpi-multi")?.closest("article");
    if (multi) {
      const title = multi.querySelector("h2");
      const note = multi.querySelector(".kpi-note");
      if (title) title.textContent = "Recoupés par plusieurs sources";
      if (note) note.textContent = "reliés à ≥ 2 sources — pas une confirmation indépendante";
    }

    const body = reliability?.querySelector(".reliability-body");
    if (body && !$("#audit-source-toolbar")) {
      const toolbar = document.createElement("div");
      toolbar.className = "audit-toolbar";
      toolbar.id = "audit-source-toolbar";
      toolbar.innerHTML = `
        <input id="audit-source-search" type="search" placeholder="Rechercher une source…" autocomplete="off">
        <select id="audit-source-status" aria-label="Filtrer les sources">
          <option value="">Tous les statuts</option><option>OK</option><option>PARTIAL</option><option>FAIL</option><option>SKIPPED</option>
        </select><span id="audit-source-count" class="audit-count"></span>`;
      const sourcesTitle = Array.from(body.querySelectorAll(".reliability-h3")).find((node) => node.textContent.trim() === "Sources");
      if (sourcesTitle) sourcesTitle.insertAdjacentElement("afterend", toolbar);
      else body.prepend(toolbar);
    }
  }

  function readFilters() {
    return {
      period: $("#f-period")?.value || "all",
      location: $("#f-location")?.value || "",
      sector: $("#f-sector")?.value || "",
      threat: $("#f-threat")?.value || "",
      source: $("#f-source")?.value || "",
      search: ($("#f-search")?.value || "").trim().toLowerCase(),
    };
  }

  function filteredIncidents() {
    const f = readFilters();
    let cutoff = "";
    if (f.period !== "all") {
      const date = new Date();
      date.setMonth(date.getMonth() - Number(f.period));
      cutoff = date.toISOString().slice(0, 10);
    }
    return state.incidents.filter((incident) => {
      const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
      const oceanLocations = new Set(["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"]);
      if (ocean && !oceanLocations.has(incident.location)) return false;
      if (cutoff && incident.date < cutoff) return false;
      if (f.location && incident.location !== f.location) return false;
      if (f.sector && incident.sector !== f.sector) return false;
      if (f.threat && incident.threat !== f.threat) return false;
      if (f.source && !(incident.sources || []).includes(f.source)) return false;
      if (f.search) {
        const text = `${incident.org} ${incident.location} ${incident.sector} ${incident.threat} ${(incident.sources || []).join(" ")}`.toLowerCase();
        if (!text.includes(f.search)) return false;
      }
      return true;
    });
  }

  function currentSort() {
    const active = $$("#incidents-table th[data-sort]").find((th) => ["ascending", "descending"].includes(th.getAttribute("aria-sort")));
    if (!active) return { key: "date", dir: -1 };
    return { key: active.dataset.sort, dir: active.getAttribute("aria-sort") === "ascending" ? 1 : -1 };
  }

  function sourceHomes() {
    const map = new Map();
    ((state.status && state.status.sources) || []).forEach((source) => {
      const url = safeUrl(source.url);
      if (url) map.set(source.id, url);
    });
    return map;
  }

  function renderSourceLinks(incident) {
    const homes = sourceHomes();
    const badges = (incident.sources || []).map((id) => {
      const url = homes.get(id);
      const label = sourceLabel(id);
      return url
        ? `<a class="source-badge" href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="Page de la source ${esc(label)}">${esc(label)}</a>`
        : `<span class="source-badge">${esc(label)}</span>`;
    }).join("");
    const links = [...new Set((incident.urls || []).map(safeUrl).filter(Boolean))];
    const evidence = links.length
      ? `<div class="evidence-links"><span>Liens observés :</span>${links.slice(0, 4).map((url, i) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="${esc(url)}">${esc(host(url))}${links.length > 1 ? ` ${i + 1}` : ""}</a>`).join("")}${links.length > 4 ? `<span>+${links.length - 4}</span>` : ""}</div>`
      : "";
    return `<div class="source-badges">${badges}</div>${evidence}`;
  }

  function observeTable() {
    const tbody = $("#incidents-table tbody");
    if (!tbody) return;
    if (tableObserver) tableObserver.disconnect();
    tableObserver = new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(() => { state.page = 1; patchAll(); }, 0);
    });
    tableObserver.observe(tbody, { childList: true, subtree: false });
  }

  function renderIncidentTable() {
    const tbody = $("#incidents-table tbody");
    if (!tbody || !state.incidents.length) return;
    const { key, dir } = currentSort();
    const rows = filteredIncidents().sort((a, b) => {
      const left = key === "items" ? (a.sources || []).length : a[key] || "";
      const right = key === "items" ? (b.sources || []).length : b[key] || "";
      return left < right ? -dir : left > right ? dir : 0;
    });
    const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * state.pageSize;
    const shown = rows.slice(start, start + state.pageSize);

    tableObserver?.disconnect();
    tbody.innerHTML = shown.map((incident) => `<tr>
      <td data-label="Date" class="num">${esc(incident.date || "—")}</td>
      <td data-label="Organisation" class="wrap-cell org-cell">${esc(incident.org || "Organisation inconnue")}</td>
      <td data-label="Territoire">${esc(incident.location || "—")}</td>
      <td data-label="Secteur">${esc(incident.sector || "—")}</td>
      <td data-label="Menace">${esc(incident.threat || "—")}</td>
      <td data-label="Sources" class="sources-cell">${renderSourceLinks(incident)}</td>
    </tr>`).join("");
    observeTable();

    if ($("#table-count")) $("#table-count").textContent = rows.length ? `${start + 1}–${Math.min(start + shown.length, rows.length)} sur ${rows.length} incidents` : "0 incident";
    let pager = $("#audit-pager");
    if (!pager) {
      pager = document.createElement("div");
      pager.id = "audit-pager";
      pager.className = "audit-pager";
      $("#incidents-table")?.closest(".table-scroll")?.insertAdjacentElement("afterend", pager);
    }
    pager.innerHTML = `<span>Page ${state.page} / ${pages}</span><div class="audit-pager-actions">
      <label>Lignes <select id="audit-page-size"><option>25</option><option>50</option><option>100</option></select></label>
      <button id="audit-prev" type="button" ${state.page <= 1 ? "disabled" : ""}>Précédent</button>
      <button id="audit-next" type="button" ${state.page >= pages ? "disabled" : ""}>Suivant</button></div>`;
    $("#audit-page-size").value = String(state.pageSize);
    $("#audit-prev")?.addEventListener("click", () => { state.page--; renderIncidentTable(); });
    $("#audit-next")?.addEventListener("click", () => { state.page++; renderIncidentTable(); });
    $("#audit-page-size")?.addEventListener("change", (event) => { state.pageSize = Number(event.target.value) || 50; state.page = 1; renderIncidentTable(); });
  }

  function renderSources() {
    const all = ((state.status && state.status.sources) || []).slice();
    let rows = all;
    const q = state.sourceSearch.toLowerCase();
    if (q) rows = rows.filter((s) => `${s.id} ${s.layer} ${s.zone} ${s.access_method}`.toLowerCase().includes(q));
    if (state.sourceStatus) rows = rows.filter((s) => s.status === state.sourceStatus);
    if ($("#audit-source-count")) $("#audit-source-count").textContent = `${rows.length} / ${all.length} source${all.length > 1 ? "s" : ""}`;
    const head = $("#sources-table thead tr");
    if (head) head.innerHTML = "<th>Source</th><th>Statut</th><th>Mesures</th><th>Dernier item</th><th>Accès</th><th>Détail</th>";
    const tbody = $("#sources-table tbody");
    if (!tbody) return;
    tbody.innerHTML = rows.map((source) => {
      const url = safeUrl(source.url);
      const name = sourceLabel(source.id);
      const sourceName = url ? `<a class="source-name" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(name)}</a>` : `<span class="source-name">${esc(name)}</span>`;
      const measures = source.id === "BONJOURLAFUITE"
        ? `${source.items_seen ?? 0} vus · ${source.items_in_window ?? 0} fenêtre · ${source.items_collected ?? 0} collectés`
        : `${source.items_seen ?? 0} vus · ${source.items_collected ?? source.items ?? 0} collectés`;
      const control = source.id === "BONJOURLAFUITE" ? "Statut OK/FAIL spécifique · pas de couverture générique" : (source.status === "SKIPPED" ? "Hors périmètre du run" : `Couverture ${source.coverage}%`);
      const latest = source.id === "BONJOURLAFUITE" ? [source.last_recognized_org, source.last_recognized_date].filter(Boolean).join(" · ") : (source.latest_item || "—");
      const detail = source.status === "FAIL" ? (source.error || source.comment || source.reason || "Échec") : (source.comment || source.reason || "");
      return `<tr>
        <td data-label="Source">${sourceName}<div class="source-meta">${esc(source.id)} · ${esc(source.layer || "")}</div></td>
        <td data-label="Statut"><span class="chip" data-status="${esc(source.status)}">${esc(source.status)}</span><div class="source-control">${esc(control)}</div></td>
        <td data-label="Mesures" class="source-measures">${esc(measures)}</td>
        <td data-label="Dernier item">${esc(latest)}</td>
        <td data-label="Accès" class="cell-clip">${esc(source.access_method || "—")}</td>
        <td data-label="Détail" class="cell-detail">${esc(detail)}</td>
      </tr>`;
    }).join("");
  }

  function patchRunLabels() {
    const data = state.status;
    if (!data || !data.run) return;
    const run = data.run;
    const c = data.counts || { ok: 0, partial: 0, fail: 0, skipped: 0 };
    const executed = c.ok + c.partial + c.fail;
    if ($("#run-pill-text")) $("#run-pill-text").textContent = run.overall === "HEALTHY" ? `Collecte OK · ${executed} source${executed > 1 ? "s" : ""}` : `Collecte à vérifier · ${c.partial + c.fail} source${c.partial + c.fail > 1 ? "s" : ""}`;
    if ($("#run-pill")) $("#run-pill").title = `Run ${run.mode} · score global ${run.health}/100 · ${c.skipped} source(s) hors périmètre`;
    if ($("#kpi-new")) {
      if (run.mode === "CREATE") $("#kpi-new").textContent = `Base reconstruite · ${run.incidents} incidents chargés`;
      else $("#kpi-new").textContent = `+${run.new_incidents} nouvel${run.new_incidents > 1 ? "s" : ""} incident${run.new_incidents > 1 ? "s" : ""}`;
    }
    if ($("#reliability-summary")) $("#reliability-summary").textContent = `${executed} exécutée${executed > 1 ? "s" : ""} · ${c.ok} OK · ${c.partial} partielle${c.partial > 1 ? "s" : ""} · ${c.fail} échec${c.fail > 1 ? "s" : ""} · ${c.skipped} hors run`;
  }

  function patchAll() {
    patchRunLabels();
    renderSources();
    renderIncidentTable();
  }

  function bindAuditControls() {
    let searchTimer;
    $("#audit-source-search")?.addEventListener("input", (event) => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state.sourceSearch = event.target.value.trim(); renderSources(); }, 120);
    });
    $("#audit-source-status")?.addEventListener("change", (event) => { state.sourceStatus = event.target.value; renderSources(); });
    document.addEventListener("cyberwatch:filters-changed", () => requestAnimationFrame(patchAll));
  }

  async function load(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-cache" });
      if (!response.ok) throw new Error(String(response.status));
      return await response.json();
    } catch (_) { return fallback; }
  }

  async function init() {
    restructure();
    bindAuditControls();
    const [incidents, status] = await Promise.all([
      load("assets/data/incidents.json", []), load("assets/data/status.json", null),
    ]);
    state.incidents = Array.isArray(incidents) ? incidents : [];
    state.status = status;
    observeTable();
    patchAll();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
