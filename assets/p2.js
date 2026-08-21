/* Cyberwatch P2 — couche produit progressive, statique et sans dépendance. */
(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const DAY = 864e5;
  const TRACKED_LOCATIONS = [
    "France métropolitaine", "La Réunion", "Mayotte", "Maurice",
    "Madagascar", "Seychelles", "Comores",
  ];
  const state = {
    incidents: [],
    status: null,
    filters: { q: "", threat: "", sector: "", location: "", source: "", period: "all" },
    sort: "date-desc",
    page: 1,
    pageSize: 30,
  };

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[char]));
  }

  function normalize(value) {
    return String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase("fr-FR").replace(/\s+/g, " ").trim();
  }

  function safeUrl(value) {
    try {
      const url = new URL(String(value || ""), location.href);
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) {
      return "";
    }
  }

  function formatDate(value, withTime = false) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(0, 10);
    return new Intl.DateTimeFormat("fr-FR", withTime
      ? { dateStyle: "medium", timeStyle: "short" }
      : { dateStyle: "medium" }).format(date);
  }

  function sourceLabel(id) {
    return ({
      BONJOURLAFUITE: "BonjourLaFuite",
      FRENCHBREACHES: "FrenchBreaches",
      CYBERATTAQUE_ORG: "Cyberattaque.org",
      RANSOMWARE_LIVE: "Ransomware.live",
      VEILLE_LLM: "Veille IA",
      CERT_MU_ALERTS: "CERT-MU",
    })[id] || String(id || "Source");
  }

  function uniqueSorted(values) {
    return Array.from(new Set(values.filter((value) => value && value !== "Inconnu")))
      .sort((a, b) => a.localeCompare(b, "fr"));
  }

  function sourceHome(id) {
    const source = (state.status?.sources || []).find((row) => row.id === id);
    return safeUrl(source?.url);
  }

  function factSearchText(facts) {
    if (!Array.isArray(facts)) return "";
    return facts.map((fact) => JSON.stringify(fact)).join(" ");
  }

  function searchable(incident) {
    return normalize([
      incident.org, incident.sector, incident.threat, incident.location,
      incident.summary, ...(incident.sources || []), ...(incident.urls || []),
      factSearchText(incident.facts), incident.local?.summary,
    ].filter(Boolean).join(" "));
  }

  function cutoffFor(period) {
    const days = Number(period);
    if (!Number.isFinite(days) || days <= 0) return null;
    return new Date(Date.now() - days * DAY);
  }

  function filtered() {
    const query = normalize(state.filters.q);
    const cutoff = cutoffFor(state.filters.period);
    return state.incidents.filter((incident) => {
      if (query && !searchable(incident).includes(query)) return false;
      if (state.filters.threat && incident.threat !== state.filters.threat) return false;
      if (state.filters.sector && incident.sector !== state.filters.sector) return false;
      if (state.filters.location && incident.location !== state.filters.location) return false;
      if (state.filters.source && !(incident.sources || []).includes(state.filters.source)) return false;
      if (cutoff) {
        const date = new Date(incident.date);
        if (Number.isNaN(date.getTime()) || date < cutoff) return false;
      }
      return true;
    });
  }

  function sorted(rows) {
    const result = rows.slice();
    if (state.sort === "date-asc") return result.sort((a, b) => String(a.date).localeCompare(String(b.date)));
    if (state.sort === "org") return result.sort((a, b) => String(a.org).localeCompare(String(b.org), "fr"));
    if (state.sort === "sources") return result.sort((a, b) => (b.sources?.length || 0) - (a.sources?.length || 0));
    return result.sort((a, b) => String(b.date).localeCompare(String(a.date)));
  }

  function countBy(rows, key) {
    const counts = new Map();
    rows.forEach((row) => {
      const value = row[key] || "Inconnu";
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    return Array.from(counts, ([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label, "fr"));
  }

  function periodCount(rows, fromDays, toDays = 0) {
    const end = new Date(Date.now() - toDays * DAY);
    const start = new Date(Date.now() - fromDays * DAY);
    return rows.filter((row) => {
      const date = new Date(row.date);
      return !Number.isNaN(date.getTime()) && date >= start && date < end;
    }).length;
  }

  function delta(current, previous) {
    if (!previous) return current ? "nouvelle activité" : "stable";
    const value = Math.round(((current - previous) / previous) * 100);
    return `${value > 0 ? "+" : ""}${value} %`;
  }

  function setOptions(select, values, allLabel) {
    const current = select.value;
    select.innerHTML = `<option value="">${esc(allLabel)}</option>` + values
      .map((value) => `<option value="${esc(value)}">${esc(value)}</option>`).join("");
    select.value = values.includes(current) ? current : "";
  }

  function injectShell() {
    const charts = $(".dashboard-charts");
    if (!charts || $("#p2-product")) return;
    const section = document.createElement("section");
    section.id = "p2-product";
    section.className = "p2-product";
    section.setAttribute("aria-labelledby", "p2-title");
    section.innerHTML = `
      <div class="p2-heading">
        <div><p class="p2-eyebrow">Exploration produit</p><h2 id="p2-title">Comprendre les incidents</h2>
        <p>Recherche transversale, filtres partageables, vues incident/organisation et tendances.</p></div>
        <button id="p2-copy-link" type="button" class="p2-secondary">Copier le lien de cette vue</button>
      </div>
      <div class="p2-filters" role="search" aria-label="Recherche avancée des incidents">
        <label class="p2-search"><span>Recherche</span><input id="p2-q" type="search" autocomplete="off" placeholder="Organisation, menace, secteur, source, synthèse…"></label>
        <label><span>Menace</span><select id="p2-threat"><option value="">Toutes</option></select></label>
        <label><span>Secteur</span><select id="p2-sector"><option value="">Tous</option></select></label>
        <label><span>Territoire</span><select id="p2-location"><option value="">Tous</option></select></label>
        <label><span>Source</span><select id="p2-source"><option value="">Toutes</option></select></label>
        <label><span>Période</span><select id="p2-period"><option value="all">Toute la base</option><option value="30">30 jours</option><option value="90">90 jours</option><option value="365">365 jours</option></select></label>
        <label><span>Tri</span><select id="p2-sort"><option value="date-desc">Plus récents</option><option value="date-asc">Plus anciens</option><option value="org">Organisation</option><option value="sources">Plus corroborés</option></select></label>
        <button id="p2-reset" type="button" class="p2-reset">Réinitialiser</button>
      </div>
      <div id="p2-active-filters" class="p2-active-filters" aria-live="polite"></div>
      <div id="p2-summary" class="p2-summary" aria-label="Résumé analytique"></div>
      <div class="p2-insights-grid">
        <article class="card p2-insight"><div class="p2-card-head"><h3>Tendance récente</h3><span>30 / 90 / 365 jours</span></div><div id="p2-trend"></div></article>
        <article class="card p2-insight"><div class="p2-card-head"><h3>Couverture géographique</h3><span>Observation publique, pas exhaustivité</span></div><div id="p2-geo"></div></article>
      </div>
      <section class="card p2-results" aria-labelledby="p2-results-title">
        <div class="p2-card-head"><div><h3 id="p2-results-title">Incidents</h3><p id="p2-count" class="muted"></p></div><div id="p2-pager-top"></div></div>
        <div id="p2-list" class="p2-list" aria-live="polite"></div>
        <div id="p2-pager" class="p2-pager"></div>
      </section>
      <p class="p2-coverage-caveat">Une absence dans Cyberwatch signifie « aucun incident publiquement observé dans les sources couvertes », jamais « aucun incident réel ».</p>
      <dialog id="p2-dialog" class="p2-dialog" aria-labelledby="p2-dialog-title"><div id="p2-dialog-content"></div><form method="dialog"><button class="p2-secondary">Fermer</button></form></dialog>`;
    charts.parentNode.insertBefore(section, charts);
    document.documentElement.classList.add("p2-active");
  }

  function readUrl() {
    const params = new URLSearchParams(location.search);
    state.filters.q = params.get("q") || "";
    state.filters.threat = params.get("threat") || "";
    state.filters.sector = params.get("sector") || "";
    state.filters.location = params.get("location") || "";
    state.filters.source = params.get("source") || "";
    state.filters.period = params.get("period") || "all";
    state.sort = params.get("sort") || "date-desc";
    state.page = Math.max(1, Number(params.get("page")) || 1);
  }

  function writeUrl() {
    const params = new URLSearchParams();
    Object.entries(state.filters).forEach(([key, value]) => {
      if (value && value !== "all") params.set(key, value);
    });
    if (state.sort !== "date-desc") params.set("sort", state.sort);
    if (state.page > 1) params.set("page", String(state.page));
    const query = params.toString();
    history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}${location.hash}`);
  }

  function syncControls() {
    $("#p2-q").value = state.filters.q;
    $("#p2-threat").value = state.filters.threat;
    $("#p2-sector").value = state.filters.sector;
    $("#p2-location").value = state.filters.location;
    $("#p2-source").value = state.filters.source;
    $("#p2-period").value = state.filters.period;
    $("#p2-sort").value = state.sort;
  }

  function renderActiveFilters() {
    const labels = [];
    if (state.filters.q) labels.push(`Recherche : “${state.filters.q}”`);
    if (state.filters.threat) labels.push(`Menace : ${state.filters.threat}`);
    if (state.filters.sector) labels.push(`Secteur : ${state.filters.sector}`);
    if (state.filters.location) labels.push(`Territoire : ${state.filters.location}`);
    if (state.filters.source) labels.push(`Source : ${sourceLabel(state.filters.source)}`);
    if (state.filters.period !== "all") labels.push(`Période : ${state.filters.period} jours`);
    $("#p2-active-filters").innerHTML = labels.length
      ? labels.map((label) => `<span>${esc(label)}</span>`).join("")
      : '<span class="muted">Aucun filtre actif.</span>';
  }

  function renderSummary(rows) {
    const current30 = periodCount(rows, 30);
    const previous30 = periodCount(rows, 60, 30);
    const uniqueOrgs = new Set(rows.map((row) => normalize(row.org)).filter(Boolean)).size;
    const multisource = rows.filter((row) => (row.sources || []).length > 1).length;
    const topThreat = countBy(rows, "threat")[0];
    const topSector = countBy(rows, "sector").find((row) => row.label !== "Inconnu");
    const cards = [
      [rows.length, "incidents dans la vue"],
      [uniqueOrgs, "organisations distinctes"],
      [`${current30} · ${delta(current30, previous30)}`, "incidents sur 30 j vs période précédente"],
      [multisource, "incidents multi-sources"],
      [topThreat?.label || "—", "menace dominante"],
      [topSector?.label || "—", "secteur dominant documenté"],
    ];
    $("#p2-summary").innerHTML = cards.map(([value, label]) => `<article><strong>${esc(value)}</strong><span>${esc(label)}</span></article>`).join("");
  }

  function renderTrend(rows) {
    const periods = [30, 90, 365];
    const values = periods.map((days) => ({ days, value: periodCount(rows, days) }));
    const max = Math.max(...values.map((row) => row.value), 1);
    $("#p2-trend").innerHTML = `<div class="p2-bars">${values.map((row) => `<div class="p2-bar-row"><span>${row.days} j</span><div class="p2-bar-track"><i style="width:${Math.max(2, Math.round(100 * row.value / max))}%"></i></div><strong>${row.value}</strong></div>`).join("")}</div>`;
  }

  function renderGeo(rows) {
    const counts = new Map(TRACKED_LOCATIONS.map((location) => [location, 0]));
    rows.forEach((row) => { if (counts.has(row.location)) counts.set(row.location, counts.get(row.location) + 1); });
    $("#p2-geo").innerHTML = `<div class="p2-geo-list">${Array.from(counts, ([location, count]) => `<button type="button" data-location="${esc(location)}" class="${count ? "" : "p2-zero"}"><span>${esc(location)}</span><strong>${count}</strong></button>`).join("")}</div><p class="muted">Un zéro est un angle mort d’observation possible, pas une preuve d’absence d’incident.</p>`;
  }

  function sourceBadges(incident) {
    return (incident.sources || []).map((id) => {
      const home = sourceHome(id);
      return home ? `<a href="${esc(home)}" target="_blank" rel="noopener noreferrer">${esc(sourceLabel(id))}</a>` : `<span>${esc(sourceLabel(id))}</span>`;
    }).join("");
  }

  function provenanceLabel(incident) {
    const count = incident.sources?.length || 0;
    if (count > 1) return `${count} sources · corroboré`;
    return count === 1 ? "1 source · mono-source" : "source non documentée";
  }

  function renderList(rows) {
    const ordered = sorted(rows);
    const pages = Math.max(1, Math.ceil(ordered.length / state.pageSize));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * state.pageSize;
    const shown = ordered.slice(start, start + state.pageSize);
    $("#p2-count").textContent = ordered.length ? `${start + 1}–${Math.min(start + shown.length, ordered.length)} sur ${ordered.length}` : "0 incident";
    $("#p2-list").innerHTML = shown.length ? shown.map((incident) => `
      <article class="p2-incident" data-id="${esc(incident.id)}">
        <div class="p2-incident-main"><div class="p2-incident-top"><time datetime="${esc(incident.date)}">${esc(formatDate(incident.date))}</time><span>${esc(incident.location || "Inconnu")}</span></div>
        <button type="button" class="p2-org-link" data-org="${esc(incident.org)}">${esc(incident.org || "Organisation inconnue")}</button>
        <p class="p2-tags"><span>${esc(incident.threat || "Inconnu")}</span><span>${esc(incident.sector || "Inconnu")}</span></p>
        ${incident.summary ? `<p class="p2-summary-text">${esc(incident.summary)}</p>` : ""}</div>
        <div class="p2-incident-side"><span class="p2-provenance">${esc(provenanceLabel(incident))}</span><div class="p2-source-badges">${sourceBadges(incident)}</div><button type="button" class="p2-detail" data-id="${esc(incident.id)}">Voir l’incident</button></div>
      </article>`).join("") : '<div class="p2-empty"><strong>Aucun résultat.</strong><p>Élargissez les filtres ou réinitialisez la recherche.</p></div>';
    const pager = `<button type="button" data-page="prev" ${state.page <= 1 ? "disabled" : ""}>Précédent</button><span>Page ${state.page} / ${pages}</span><button type="button" data-page="next" ${state.page >= pages ? "disabled" : ""}>Suivant</button>`;
    $("#p2-pager").innerHTML = pager;
    $("#p2-pager-top").innerHTML = `<span class="muted">${ordered.length} résultat${ordered.length > 1 ? "s" : ""}</span>`;
  }

  function detailFacts(incident) {
    const facts = Array.isArray(incident.facts) ? incident.facts : [];
    if (!facts.length) return '<p class="muted">Aucun fait structuré supplémentaire disponible.</p>';
    return facts.map((fact) => {
      const rows = [
        ["Source", sourceLabel(fact.source)], ["Statut", fact.claim_status], ["Acteur", fact.threat_actor],
        ["Tiers", fact.third_party], ["Localisation précise", fact.fine_location], ["Impact", fact.impact],
        ["Date d’attaque", fact.attack_date], ["Découverte", fact.discovered_date],
      ].filter(([, value]) => value);
      return `<div class="p2-fact"><strong>${esc(sourceLabel(fact.source))}</strong>${rows.map(([label, value]) => `<div><span>${esc(label)}</span><b>${esc(value)}</b></div>`).join("")}</div>`;
    }).join("");
  }

  function openIncident(id) {
    const incident = state.incidents.find((row) => row.id === id);
    if (!incident) return;
    const links = Array.from(new Set((incident.urls || []).map(safeUrl).filter(Boolean)));
    $("#p2-dialog-content").innerHTML = `
      <p class="p2-eyebrow">Incident</p><h2 id="p2-dialog-title">${esc(incident.org || "Organisation inconnue")}</h2>
      <div class="p2-detail-grid"><div><span>Date</span><strong>${esc(formatDate(incident.date))}</strong><small>${esc(incident.basis || "")}</small></div><div><span>Menace</span><strong>${esc(incident.threat || "Inconnu")}</strong></div><div><span>Secteur</span><strong>${esc(incident.sector || "Inconnu")}</strong></div><div><span>Territoire</span><strong>${esc(incident.location || "Inconnu")}</strong></div><div><span>Première observation</span><strong>${esc(formatDate(incident.first_seen, true))}</strong></div><div><span>Dernière observation</span><strong>${esc(formatDate(incident.last_seen, true))}</strong></div></div>
      <p class="p2-provenance-block"><strong>${esc(provenanceLabel(incident))}</strong> · ${esc((incident.sources || []).map(sourceLabel).join(" · "))}</p>
      ${incident.summary ? `<div class="p2-dialog-summary"><strong>Synthèse</strong><p>${esc(incident.summary)}</p></div>` : ""}
      ${links.length ? `<div class="p2-evidence"><strong>Références</strong>${links.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(new URL(url).hostname.replace(/^www\./, ""))}</a>`).join("")}</div>` : ""}
      <div class="p2-facts"><h3>Éléments documentés</h3>${detailFacts(incident)}</div>`;
    $("#p2-dialog").showModal();
  }

  function openOrganisation(name) {
    const key = normalize(name);
    const rows = state.incidents.filter((row) => normalize(row.org) === key).sort((a, b) => String(b.date).localeCompare(String(a.date)));
    if (!rows.length) return;
    const threats = countBy(rows, "threat");
    const sources = uniqueSorted(rows.flatMap((row) => row.sources || [])).map(sourceLabel);
    $("#p2-dialog-content").innerHTML = `
      <p class="p2-eyebrow">Organisation</p><h2 id="p2-dialog-title">${esc(name)}</h2>
      <div class="p2-detail-grid"><div><span>Incidents</span><strong>${rows.length}</strong></div><div><span>Premier incident observé</span><strong>${esc(formatDate(rows[rows.length - 1].date))}</strong></div><div><span>Dernier incident observé</span><strong>${esc(formatDate(rows[0].date))}</strong></div><div><span>Sources</span><strong>${esc(sources.join(" · ") || "—")}</strong></div></div>
      <div class="p2-dialog-summary"><strong>Menaces observées</strong><p>${esc(threats.map((row) => `${row.label} (${row.value})`).join(" · "))}</p></div>
      <div class="p2-org-history"><h3>Chronologie</h3>${rows.map((row) => `<button type="button" class="p2-history-row" data-id="${esc(row.id)}"><time>${esc(formatDate(row.date))}</time><span>${esc(row.threat || "Inconnu")}</span><small>${esc(row.location || "Inconnu")}</small></button>`).join("")}</div>`;
    $("#p2-dialog").showModal();
  }

  function render() {
    writeUrl();
    renderActiveFilters();
    const rows = filtered();
    renderSummary(rows);
    renderTrend(rows);
    renderGeo(rows);
    renderList(rows);
  }

  function bind() {
    let timer;
    $("#p2-q").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => { state.filters.q = event.target.value; state.page = 1; render(); }, 120);
    });
    ["threat", "sector", "location", "source", "period"].forEach((key) => {
      $(`#p2-${key}`).addEventListener("change", (event) => { state.filters[key] = event.target.value; state.page = 1; render(); });
    });
    $("#p2-sort").addEventListener("change", (event) => { state.sort = event.target.value; state.page = 1; render(); });
    $("#p2-reset").addEventListener("click", () => {
      state.filters = { q: "", threat: "", sector: "", location: "", source: "", period: "all" };
      state.sort = "date-desc"; state.page = 1; syncControls(); render();
    });
    $("#p2-copy-link").addEventListener("click", async (event) => {
      writeUrl();
      try { await navigator.clipboard.writeText(location.href); event.target.textContent = "Lien copié"; }
      catch (_) { event.target.textContent = "URL prête à partager"; }
      setTimeout(() => { event.target.textContent = "Copier le lien de cette vue"; }, 1800);
    });
    $("#p2-product").addEventListener("click", (event) => {
      const detail = event.target.closest(".p2-detail, .p2-history-row");
      if (detail) return openIncident(detail.dataset.id);
      const org = event.target.closest(".p2-org-link");
      if (org) return openOrganisation(org.dataset.org);
      const geo = event.target.closest("[data-location]");
      if (geo) { state.filters.location = geo.dataset.location; state.page = 1; syncControls(); return render(); }
      const page = event.target.closest("[data-page]");
      if (page) { state.page += page.dataset.page === "next" ? 1 : -1; render(); $("#p2-results-title").scrollIntoView({ behavior: "smooth", block: "start" }); }
    });
    addEventListener("popstate", () => { readUrl(); syncControls(); render(); });
  }

  async function load(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-cache" });
      if (!response.ok) throw new Error(String(response.status));
      return await response.json();
    } catch (error) {
      console.warn(`P2: données indisponibles ${path}`, error);
      return fallback;
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    injectShell();
    readUrl();
    const [incidents, status] = await Promise.all([
      load("assets/data/incidents.json", []),
      load("assets/data/status.json", null),
    ]);
    state.incidents = Array.isArray(incidents) ? incidents : [];
    state.status = status;
    setOptions($("#p2-threat"), uniqueSorted(state.incidents.map((row) => row.threat)), "Toutes");
    setOptions($("#p2-sector"), uniqueSorted(state.incidents.map((row) => row.sector)), "Tous");
    setOptions($("#p2-location"), uniqueSorted(state.incidents.map((row) => row.location)), "Tous");
    setOptions($("#p2-source"), uniqueSorted(state.incidents.flatMap((row) => row.sources || [])), "Toutes");
    syncControls();
    bind();
    render();
  });
})();
