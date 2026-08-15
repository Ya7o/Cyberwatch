/* Cyberwatch — correctifs d'audit UI appliqués au dashboard historique. */
(() => {
  "use strict";

  const state = {
    incidents: [],
    status: null,
    page: 1,
    pageSize: 50,
  };
  let tableObserver = null;
  let timer = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const AUTOMOTIVE_ORGS = new Set(["groupe courtois automobiles"]);
  const LARGE_RETAIL_ORGS = new Set([
    "auchan", "intermarché", "intermarché drive", "lidl", "magasins u",
    "système u", "super u",
  ]);
  const orgKey = (value) => String(value || "").trim().toLocaleLowerCase("fr-FR");
  /** Même dérivation qu'app-legacy.js : zone Mayotte + couche LOCAL_MEDIA_DIRECT,
   * jamais une liste codée en dur ; exclut les candidates (angles morts, etc.). */
  const mahoranPressSources = () => new Set(
    ((state.status && state.status.sources) || [])
      .filter((source) => source.zone === "Mayotte" && source.layer === "LOCAL_MEDIA_DIRECT")
      .map((source) => source.id)
  );
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
      VEILLE_LLM: "Veille LLM",
      CERT_MU_ALERTS: "CERT-MU",
      KWEZI_NUMERIQUE: "Kwezi",
      MAYOTTE_HEBDO_NUMERIQUE: "Mayotte Hebdo",
      JOURNAL_DE_MAYOTTE: "Journal de Mayotte",
      MAYOTTE_FM: "Mayotte FM",
      MAYOTTE_LA_1ERE: "Mayotte La 1ère",
      FLASH_INFOS_MAYOTTE: "Flash Infos Mayotte",
      FRANCE_MAYOTTE_MATIN: "France Mayotte Matin",
      LES_NOUVELLES_DE_MAYOTTE: "Les Nouvelles de Mayotte",
      RMV_ACTUALITES: "RMV Actualités",
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
      .incidents-card .table-scroll{max-height:none}
      .audit-pager{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:12.5px;color:var(--text-secondary)}
      .audit-pager button,.audit-pager select{font:inherit;font-size:13px;padding:6px 9px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-primary)}
      .audit-pager{justify-content:space-between;margin-top:12px}.audit-pager-actions{display:flex;gap:8px;align-items:center}.audit-pager button:disabled{opacity:.45}
      .source-name{font-weight:650}.source-meta,.source-control{font-size:11.5px;color:var(--text-secondary)}
      .sources-list{display:flex;gap:9px 18px;flex-wrap:wrap;margin-top:12px}.source-state{display:inline-flex;align-items:center;gap:7px;font-size:14px}.source-led{width:9px;height:9px;border-radius:50%;background:var(--text-muted);box-shadow:0 0 0 2px var(--surface)}.source-led--ok{background:var(--ok,#2f9e44)}.source-led--attention{background:var(--warn,#d99a00)}.source-led--fail{background:var(--danger,#d64545)}
      .source-badges{display:flex;gap:5px;flex-wrap:wrap}.source-badge{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;background:var(--plane);font-size:11.5px;text-decoration:none;color:var(--text-secondary)}
      .source-badge:hover{color:var(--text-primary)}.evidence-links{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:11.5px;color:var(--text-secondary)}
      #sources-table{table-layout:auto!important}#sources-table td,#sources-table th{width:auto!important;vertical-align:top}.source-measures{white-space:normal!important}
      @media(max-width:700px){
        .topbar-inner{align-items:flex-start}.brand-sub{max-width:190px}.run-pill{white-space:normal;text-align:left}
        .incidents-card .table-scroll,.reliability .table-scroll{overflow:visible;max-height:none}
        #incidents-table thead,#sources-table thead{display:none}
        #incidents-table,#incidents-table tbody,#incidents-table tr,#incidents-table td,#sources-table,#sources-table tbody,#sources-table tr,#sources-table td{display:block;width:100%}
        #incidents-table tr,#sources-table tr{padding:11px 0;border-bottom:1px solid var(--grid)}
        #incidents-table td,#sources-table td{border:0!important;padding:3px 0!important;white-space:normal!important;max-width:none!important;overflow:visible!important;width:auto!important}
        #incidents-table td[data-label]::before,#sources-table td[data-label]::before{content:attr(data-label);display:inline-block;min-width:88px;margin-right:8px;color:var(--text-muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;vertical-align:top}
        #incidents-table .org-cell{font-size:16px;font-weight:650;padding-bottom:7px!important}#incidents-table .org-cell::before{display:none}
        #incidents-table .sources-cell::before{display:block;margin-bottom:4px}
        .audit-pager{align-items:flex-start}.audit-pager-actions{width:100%;justify-content:space-between}
      }
    `;
    document.head.appendChild(style);
  }

  function restructure() {
    installCss();
    if ($(".reliability-title")) $(".reliability-title").textContent = "État des sources";
    const incidentCard = $("#incidents-table")?.closest("section.card");
    if (incidentCard) incidentCard.classList.add("incidents-card");

  }

  function filteredIncidents() {
    const pressOnly = $("#f-presse-mahoraise")?.getAttribute("aria-pressed") === "true";
    const veilleLlmOnly = $("#f-veille-llm")?.getAttribute("aria-pressed") === "true";
    const press = pressOnly ? mahoranPressSources() : null;
    return state.incidents.filter((incident) => {
      const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
      const automotive = $("#f-auto")?.getAttribute("aria-pressed") === "true";
      const largeRetail = $("#f-grande-distrib")?.getAttribute("aria-pressed") === "true";
      const oceanLocations = new Set(["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"]);
      if (ocean && !oceanLocations.has(incident.location)) return false;
      if (press && !(incident.sources || []).some((source) => press.has(source))) return false;
      if (veilleLlmOnly && !(incident.provenance_tags || []).includes("veille_llm")) return false;
      if ((automotive || largeRetail) && !(
        (automotive && AUTOMOTIVE_ORGS.has(orgKey(incident.org)))
        || (largeRetail && LARGE_RETAIL_ORGS.has(orgKey(incident.org)))
      )) return false;
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
      <label>Lignes <select id="audit-page-size"><option>25</option><option>50</option><option>100</option><option>500</option><option>1000</option></select></label>
      <button id="audit-prev" type="button" ${state.page <= 1 ? "disabled" : ""}>Précédent</button>
      <button id="audit-next" type="button" ${state.page >= pages ? "disabled" : ""}>Suivant</button></div>`;
    $("#audit-page-size").value = String(state.pageSize);
    $("#audit-prev")?.addEventListener("click", () => { state.page--; renderIncidentTable(); });
    $("#audit-next")?.addEventListener("click", () => { state.page++; renderIncidentTable(); });
    $("#audit-page-size")?.addEventListener("change", (event) => { state.pageSize = Number(event.target.value) || 50; state.page = 1; renderIncidentTable(); });
  }

  function renderSources() {
    const rows = ((state.status && state.status.sources) || []).slice();
    const list = $("#sources-list");
    if (!list) return;
    list.innerHTML = rows.map((source) => {
      const status = String(source.status || "SKIPPED").toUpperCase();
      const level = status === "OK" ? "ok" : (status === "FAIL" ? "fail" : "attention");
      return `<span class="source-state"><span class="source-led source-led--${level}" role="img" aria-label="${esc(status)}" title="${esc(status)}"></span>${esc(sourceLabel(source.id))}</span>`;
    }).join("");
  }

  function patchRunLabels() {
    const data = state.status;
    if (!data || !data.run || data.initialized === false) return;
    const run = data.run;
    const c = data.counts || { ok: 0, partial: 0, fail: 0, skipped: 0 };
    const totalSources = (data.sources || []).length || c.ok + c.partial + c.fail + c.skipped;
    const needsAttention = (data.blind_spots || []).length;
    if ($("#run-pill-text")) $("#run-pill-text").textContent = needsAttention ? `Sources : ${c.ok}/${totalSources} opérationnelles · ${needsAttention} à vérifier` : `Sources : ${c.ok}/${totalSources} opérationnelles`;
    if ($("#run-pill")) $("#run-pill").title = "Voir l’état détaillé des sources";
    if ($("#reliability-summary")) $("#reliability-summary").textContent = needsAttention ? `${c.ok}/${totalSources} sources opérationnelles · ${needsAttention} à vérifier` : `${c.ok}/${totalSources} sources opérationnelles · aucune anomalie signalée`;
  }

  function patchAll() {
    patchRunLabels();
    renderSources();
    renderIncidentTable();
  }

  function bindAuditControls() {
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
