/* Cyberwatch — parcours consultant, à partir des données canoniques publiées. */
(() => {
  "use strict";
  const DAY = 864e5;
  const FRESHNESS_WARNING_HOURS = 30;
  const FRESHNESS_STALE_HOURS = 36;
  const PAGE_SIZE = 30;
  const VEILLE_SIZE = 15;
  const UNKNOWN = "Inconnu";
  const OCEAN_LOCATIONS = ["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"];
  const SOURCE_LABELS = {
    RANSOMWARE_LIVE: "Ransomware.live", CYBERATTAQUE_ORG: "Cyberattaque.org",
    FRENCHBREACHES: "FrenchBreaches", BONJOURLAFUITE: "BonjourLaFuite",
    VEILLE_LLM: "Veille locale Réunion / Mayotte",
  };
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const normalize = (value) => String(value ?? "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  const known = (value) => Boolean(String(value ?? "").trim()) && String(value).trim() !== UNKNOWN;
  const unique = (values) => Array.from(new Set(values.filter(Boolean)));
  const formatNumber = (value) => new Intl.NumberFormat("fr-FR").format(Number(value));
  const readStorage = (scope, key) => { try { return window[scope]?.getItem(key) || ""; } catch (_) { return ""; } };
  const writeStorage = (scope, key, value) => { try { window[scope]?.setItem(key, value); } catch (_) { /* Le stockage est facultatif. */ } };
  const formatDate = (value) => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }).format(date) : "Date non déterminée";
  };
  const formatDateTime = (value) => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date) : "Date indisponible";
  };
  const safeUrl = (value) => {
    try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password ? url.href : ""; }
    catch (_) { return ""; }
  };
  const host = (value) => { try { return new URL(value).hostname.replace(/^www\./, ""); } catch (_) { return "Source"; } };
  const cleanSummary = (value) => String(value || "").replace(/^Éléments documentés\s*:\s*/i, "").replace(/^Impact documenté\s*:\s*/i, "").replace(/\s*;\s*données concernées\s*:\s*/i, ". Données exposées : ").replace(/\s+/g, " ").trim();
  const emptyFilters = () => ({ q: "", threat: "", sector: "", locations: [], source: "", period: "all", admission: "" });
  const state = {
    view: "veille", scope: "all", analysisScope: "all", analysisPeriod: "90",
    latest: [], incidents: [], incidentsLoaded: false, facts: null, status: null,
    filters: emptyFilters(), sort: "date-desc", page: 1, veillePage: 1, incidentId: "", diagnostic: false,
    loadErrors: new Set(),
  };
  const focusLocations = () => state.status?.focus_locations || ["La Réunion", "Mayotte"];
  const sourceLabel = (id) => state.status?.labels?.sources?.[id] || SOURCE_LABELS[id] || id || "Source";
  const scopeLocations = (scope) => scope === "focus" ? focusLocations().slice() : scope === "ocean" ? OCEAN_LOCATIONS.slice() : scope === "metro" ? ["France métropolitaine"] : [];
  const integrity = () => state.status?.integrity || {};
  const trendsReady = () => integrity().known === true && integrity().trend_ready === true;
  const freshness = (value) => {
    const date = value ? new Date(value) : null;
    if (!date || Number.isNaN(date.getTime())) return { status: "unknown", hours: null };
    const hours = Math.max(0, (Date.now() - date.getTime()) / 36e5);
    return { status: hours >= FRESHNESS_STALE_HOURS ? "stale" : hours >= FRESHNESS_WARNING_HOURS ? "warning" : "fresh", hours };
  };
  let incidentsPromise = null;
  let factsPromise = null;
  let detailToken = 0;
  let regionalWatchInitialized = false;

  async function loadJson(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) throw new Error(`${response.status}`);
      const value = await response.json();
      state.loadErrors.delete(path);
      return value;
    } catch (error) {
      state.loadErrors.add(path);
      console.error(`Cyberwatch : chargement impossible de ${path}`, error);
      return fallback;
    }
  }

  async function ensureIncidents() {
    if (state.incidentsLoaded) return state.incidents;
    if (!incidentsPromise) incidentsPromise = loadJson("assets/data/incidents.json", []);
    const rows = await incidentsPromise;
    state.incidents = Array.isArray(rows) ? rows : [];
    state.incidentsLoaded = !state.loadErrors.has("assets/data/incidents.json");
    if (!state.incidentsLoaded) incidentsPromise = null;
    return state.incidents;
  }

  function readUrl() {
    const params = new URLSearchParams(location.search);
    state.view = ["veille", "recherche", "analyse"].includes(params.get("vue")) ? params.get("vue") : "veille";
    const scope = ["all", "focus", "ocean", "metro"].includes(params.get("scope")) ? params.get("scope") : "all";
    if (state.view === "veille") {
      state.scope = scope;
      state.veillePage = Math.max(1, Math.floor(Number(params.get("page")) || 1));
    }
    if (state.view === "analyse") {
      state.analysisScope = scope;
      state.analysisPeriod = ["30", "90", "365", "all"].includes(params.get("period")) ? params.get("period") : "90";
    }
    if (state.view === "recherche") {
      state.filters = emptyFilters();
      ["q", "threat", "sector", "source"].forEach((key) => { state.filters[key] = params.get(key) || ""; });
      state.filters.locations = unique(params.getAll("location"));
      state.filters.period = ["30", "90", "365"].includes(params.get("period")) ? params.get("period") : "all";
      state.filters.admission = ["ACCEPTED", "CANDIDATE"].includes(params.get("admission")) ? params.get("admission") : "";
      state.sort = ["date-asc", "org"].includes(params.get("sort")) ? params.get("sort") : "date-desc";
      state.page = Math.max(1, Math.floor(Number(params.get("page")) || 1));
    }
    state.incidentId = params.get("incident") || "";
    state.diagnostic = params.get("diagnostic") === "1";
  }

  function syncUrl(push = false) {
    const params = new URLSearchParams();
    if (state.view !== "veille") params.set("vue", state.view);
    if (state.view === "veille" && state.scope !== "all") params.set("scope", state.scope);
    if (state.view === "veille" && state.veillePage > 1) params.set("page", String(state.veillePage));
    if (state.view === "analyse") {
      if (state.analysisScope !== "all") params.set("scope", state.analysisScope);
      if (state.analysisPeriod !== "90") params.set("period", state.analysisPeriod);
    }
    if (state.view === "recherche") {
      ["q", "threat", "sector", "source", "admission"].forEach((key) => { if (state.filters[key]) params.set(key, state.filters[key]); });
      state.filters.locations.forEach((value) => params.append("location", value));
      if (state.filters.period !== "all") params.set("period", state.filters.period);
      if (state.sort !== "date-desc") params.set("sort", state.sort);
      if (state.page > 1) params.set("page", String(state.page));
    }
    if (state.incidentId) params.set("incident", state.incidentId);
    if (state.diagnostic) params.set("diagnostic", "1");
    const query = params.toString();
    const url = `${location.pathname}${query ? `?${query}` : ""}`;
    if (push) history.pushState(null, "", url); else history.replaceState(null, "", url);
  }

  function sourceBadges(incident) {
    const links = unique((incident.source_links || []).map((link) => safeUrl(link.url))).filter(Boolean);
    if (!links.length) return '<span class="source-unavailable">Publication directe indisponible</span>';
    return links.map((url) => {
      const link = incident.source_links.find((value) => safeUrl(value.url) === url);
      return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(link.label || host(url))}</a>`;
    }).join("");
  }

  function sectorLabel(incident) {
    if (known(incident.sector)) {
      const status = incident.sector_status?.status;
      const suffix = status === "reported" ? " (déclaré)" : ["inferred", "inferred_low"].includes(status) ? " (estimé)" : "";
      return incident.sector + suffix;
    }
    return known(incident.sector_tentative) ? `${incident.sector_tentative} (supposé)` : "";
  }

  function threatLabel(incident) {
    if (!known(incident.threat) || incident.threat === "Autre cyber") return "Nature non déterminée";
    const status = incident.threat_status?.status;
    return incident.threat + (status === "claimed" ? " (revendiqué)" : "");
  }

  function exposureLabel(incident) {
    return [incident.credentials_or_secrets_exposed ? "Identifiants exposés" : "", incident.high_sensitivity_data_exposed ? "Données très sensibles signalées" : ""].filter(Boolean).join(" · ");
  }

  function incidentCardHtml(incident) {
    const sector = sectorLabel(incident);
    const exposure = exposureLabel(incident);
    const summary = cleanSummary(incident.summary);
    const candidate = incident.admission === "CANDIDATE";
    const regional = OCEAN_LOCATIONS.includes(incident.location);
    const accessibleName = [`Ouvrir la fiche de ${incident.org || "l’organisation inconnue"}`, known(incident.location) ? incident.location : "", threatLabel(incident), candidate ? "À confirmer" : "", exposure].filter(Boolean).join(" · ");
    return `<article class="incident-card${regional ? " incident-card-regional" : ""}" data-id="${esc(incident.id)}" data-open-id="${esc(incident.id)}" role="button" tabindex="0" aria-haspopup="dialog" aria-label="${esc(accessibleName)}">
      <div class="incident-card-top"><time datetime="${esc(incident.date || "")}">${esc(formatDate(incident.date))}</time>${known(incident.location) ? `<span class="incident-location${regional ? " incident-location-regional" : ""}">${esc(incident.location)}</span>` : ""}${candidate ? '<span class="candidate-status">À confirmer</span>' : ""}</div>
      <h3 class="incident-org-link">${esc(incident.org || "Organisation inconnue")}</h3>
      <p class="incident-meta">${esc([threatLabel(incident), sector].filter(Boolean).join(" · "))}</p>
      ${summary ? `<p class="incident-summary-text">${esc(summary)}</p>` : ""}
      ${exposure ? `<p class="incident-exposure">${esc(exposure)}</p>` : ""}
    </article>`;
  }

  function renderHeader() {
    const sources = state.status?.sources || [];
    const age = freshness(state.status?.run?.as_of);
    const stamp = formatDateTime(state.status?.run?.as_of);
    const partial = sources.some((source) => source.status !== "OK");
    const freshnessLabel = age.status === "stale" ? `Données périmées · ${stamp}` : age.status === "warning" ? `Mise à jour en retard · ${stamp}` : age.status === "fresh" ? `${partial ? "Couverture partielle" : "À jour"} · ${stamp}` : "Date indisponible";
    $("#run-pill-text").textContent = freshnessLabel;
    $("#run-pill").dataset.status = age.status === "stale" ? "stale" : age.status === "fresh" && !partial ? "ok" : "degraded";
    $("#run-pill").title = "Voir l’état de la veille et les sources";
  }

  function renderIntegrityAlert() {
    const age = freshness(state.status?.run?.as_of);
    const meta = integrity();
    const alert = $("#data-alert");
    const messages = [];
    if (meta.known && Number(meta.days) < 30) messages.push(`${meta.days} jours de couverture continue disponibles.`);
    if (age.status === "stale" || age.status === "warning") messages.push(`Dernière mise à jour : ${formatDateTime(state.status?.run?.as_of)}.`);
    if (age.status === "unknown") messages.push("La date de mise à jour est indisponible.");
    if (state.loadErrors.size) messages.push("Certaines données n’ont pas pu être chargées. Réessayez en actualisant la page.");
    alert.hidden = messages.length === 0;
    alert.dataset.status = age.status === "stale" ? "stale" : "warning";
    alert.querySelector("strong").textContent = state.loadErrors.size ? "Chargement incomplet." : age.status === "stale" ? "Données périmées." : "Couverture limitée.";
    $("#data-alert-detail").textContent = messages.join(" ");
  }

  function renderPager(container, page, pages) {
    container.hidden = pages <= 1;
    container.innerHTML = pages <= 1 ? "" : `<button type="button" class="btn" data-page="prev" ${page <= 1 ? "disabled" : ""}>← Précédent</button><span role="status" aria-live="polite">Page ${page} sur ${pages}</span><button type="button" class="btn" data-page="next" ${page >= pages ? "disabled" : ""}>Suivant →</button>`;
  }

  function renderRegionalWatch() {
    const panel = $("#regional-watch");
    const bounds = periodBounds("90");
    const rows = state.incidentsLoaded && bounds ? state.incidents.filter((incident) => {
      const day = new Date(`${String(incident.date || "").slice(0, 10)}T00:00:00Z`);
      return OCEAN_LOCATIONS.includes(incident.location) && day >= bounds.start && day <= bounds.end;
    }).sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")) || String(b.id).localeCompare(String(a.id))) : [];
    const available = state.incidentsLoaded && Boolean(bounds);
    const candidates = rows.filter((row) => row.admission === "CANDIDATE").length;
    const admitted = rows.length - candidates;
    $("#regional-watch-count").textContent = available ? `${formatNumber(admitted)} incident${admitted > 1 ? "s" : ""} retenu${admitted > 1 ? "s" : ""}${candidates ? ` · ${formatNumber(candidates)} à confirmer` : ""} · 3 derniers mois` : "Veille régionale indisponible";
    const pending = state.incidents.filter((row) => focusLocations().includes(row.location) && row.admission === "CANDIDATE").length;
    $("#regional-candidates").hidden = !state.incidentsLoaded || !pending;
    $("#regional-candidates").textContent = `Voir les ${formatNumber(pending)} signaux à confirmer — toute la base Réunion / Mayotte`;
    $("#regional-watch-period").textContent = available ? rows.length ? `90 derniers jours · du ${formatDate(bounds.start)} au ${formatDate(bounds.end)}` : "Aucun incident publié dans l’océan Indien sur les 90 derniers jours." : "La période ou les données n’ont pas pu être chargées. Actualisez la page pour réessayer.";
    $("#regional-watch-locations").innerHTML = OCEAN_LOCATIONS.map((name) => ({ name, count: rows.filter((row) => row.location === name).length })).filter((row) => row.count).map((row) => `<span>${esc(row.name)} <strong>${row.count}</strong></span>`).join("");
    $("#regional-watch-list").innerHTML = rows.map(incidentCardHtml).join("");
    if (!regionalWatchInitialized || !rows.length) panel.open = rows.length > 0;
    regionalWatchInitialized = true;
  }

  function renderVeille() {
    renderRegionalWatch();
    $("#v-scope").value = state.scope;
    const locations = scopeLocations(state.scope);
    const corpus = state.incidentsLoaded ? state.incidents : state.latest;
    const rows = corpus.filter((row) => !locations.length || locations.includes(row.location)).slice().sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")) || String(b.id).localeCompare(String(a.id)));
    const pages = Math.max(1, Math.ceil(rows.length / VEILLE_SIZE));
    state.veillePage = Math.min(state.veillePage, pages);
    const start = (state.veillePage - 1) * VEILLE_SIZE;
    const shown = rows.slice(start, start + VEILLE_SIZE);
    $("#veille-count").textContent = `${formatNumber(rows.length)} incident${rows.length > 1 ? "s" : ""} · ${state.incidentsLoaded ? "Toute la base" : "Liste partielle · 30 jours"}${rows.length ? ` · ${start + 1}–${start + shown.length}` : ""}`;
    $("#veille-list").innerHTML = shown.length ? shown.map(incidentCardHtml).join("") : '<p class="empty-state">Aucun incident publié dans ce périmètre.</p>';
    renderPager($("#veille-pager"), state.veillePage, pages);
  }

  function optionHtml(values, current, allLabel) {
    return `<option value="">${esc(allLabel)}</option>` + values.map((value) => `<option value="${esc(value)}" ${value === current ? "selected" : ""}>${esc(value === UNKNOWN ? "Non déterminé" : value)}</option>`).join("");
  }

  function populateSearchControls() {
    const values = (field) => unique(state.incidents.map((row) => String(row[field] || UNKNOWN))).sort((a, b) => a.localeCompare(b, "fr"));
    $("#s-threat").innerHTML = optionHtml(values("threat"), state.filters.threat, "Toutes");
    $("#s-sector").innerHTML = optionHtml(values("sector"), state.filters.sector, "Tous");
    const sources = unique(state.incidents.flatMap((row) => row.sources || [])).sort((a, b) => sourceLabel(a).localeCompare(sourceLabel(b), "fr"));
    $("#s-source").innerHTML = '<option value="">Toutes</option>' + sources.map((id) => `<option value="${esc(id)}">${esc(sourceLabel(id))}</option>`).join("");
    const locations = unique([...values("location"), ...state.filters.locations]);
    $("#s-locations").innerHTML = locations.map((value) => `<label><input type="checkbox" value="${esc(value)}"><span>${esc(value === UNKNOWN ? "Non déterminé" : value)}</span></label>`).join("");
  }

  function updateSearchControls() {
    ["q", "threat", "sector", "source", "period", "admission"].forEach((key) => { $("#s-" + key).value = state.filters[key]; });
    $("#s-sort").value = state.sort;
    $$("#s-locations input").forEach((input) => { input.checked = state.filters.locations.includes(input.value); });
    const names = state.filters.locations;
    $("#location-toggle").textContent = !names.length ? "Tous les territoires" : names.length === 1 ? names[0] : names.every((name) => focusLocations().includes(name)) && names.length === focusLocations().length ? "Réunion / Mayotte" : `${names.length} territoires`;
  }

  function periodBounds(period) {
    if (period === "all") return null;
    const stamp = String(state.status?.run?.as_of || "").slice(0, 10);
    const end = new Date(`${stamp}T00:00:00Z`);
    if (Number.isNaN(end.getTime())) return null;
    return { start: new Date(end.getTime() - (Number(period) - 1) * DAY), end };
  }

  function filteredSearch() {
    const query = normalize(state.filters.q);
    const bounds = periodBounds(state.filters.period);
    if (state.filters.period !== "all" && !bounds) return [];
    return state.incidents.filter((incident) => {
      const searchText = normalize([incident.org, incident.threat, incident.sector, incident.location, incident.summary, ...(incident.sources || []).map(sourceLabel)].join(" "));
      if (query && !searchText.includes(query)) return false;
      if (state.filters.threat && String(incident.threat || UNKNOWN) !== state.filters.threat) return false;
      if (state.filters.sector && String(incident.sector || UNKNOWN) !== state.filters.sector) return false;
      if (state.filters.locations.length && !state.filters.locations.includes(String(incident.location || UNKNOWN))) return false;
      if (state.filters.source && !(incident.sources || []).includes(state.filters.source)) return false;
      if (state.filters.admission && (incident.admission || "ACCEPTED") !== state.filters.admission) return false;
      if (bounds) {
        const day = new Date(`${String(incident.date || "").slice(0, 10)}T00:00:00Z`);
        if (Number.isNaN(day.getTime()) || day < bounds.start || day > bounds.end) return false;
      }
      return true;
    });
  }

  function sortedSearch(rows) {
    return rows.slice().sort((a, b) => state.sort === "org" ? String(a.org || "").localeCompare(String(b.org || ""), "fr") : state.sort === "date-asc" ? String(a.date || "").localeCompare(String(b.date || "")) : String(b.date || "").localeCompare(String(a.date || "")) || String(b.id).localeCompare(String(a.id)));
  }

  function renderActiveFilters() {
    const filters = [];
    const add = (key, label, value = "") => filters.push(`<button type="button" class="filter-chip" data-remove-filter="${key}" data-value="${esc(value)}" aria-label="Retirer ${esc(label)}">${esc(label)} <span aria-hidden="true">×</span></button>`);
    if (state.filters.q) add("q", `Recherche : ${state.filters.q}`);
    if (state.filters.threat) add("threat", `Menace : ${state.filters.threat === UNKNOWN ? "non déterminée" : state.filters.threat}`);
    if (state.filters.sector) add("sector", `Secteur : ${state.filters.sector === UNKNOWN ? "non déterminé" : state.filters.sector}`);
    state.filters.locations.forEach((value) => add("locations", value, value));
    if (state.filters.source) add("source", sourceLabel(state.filters.source));
    if (state.filters.period !== "all") add("period", `${state.filters.period} jours`);
    if (state.filters.admission) add("admission", state.filters.admission === "ACCEPTED" ? "Incidents retenus" : "À confirmer");
    $("#s-active-filters").innerHTML = filters.join("");
    $("#s-reset").hidden = filters.length === 0;
  }

  function renderRecherche() {
    updateSearchControls();
    renderActiveFilters();
    const rows = sortedSearch(filteredSearch());
    const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * PAGE_SIZE;
    const shown = rows.slice(start, start + PAGE_SIZE);
    $("#s-count").textContent = `${formatNumber(rows.length)} incident${rows.length > 1 ? "s" : ""}${rows.length && pages > 1 ? ` · ${start + 1}–${start + shown.length}` : ""}`;
    $("#s-list").innerHTML = !state.incidentsLoaded ? '<p class="empty-state">La liste n’a pas pu être chargée. Actualisez la page pour réessayer.</p>' : state.filters.period !== "all" && !periodBounds(state.filters.period) ? '<p class="empty-state">Période indisponible : la date du snapshot manque.</p>' : shown.length ? shown.map(incidentCardHtml).join("") : '<p class="empty-state">Aucun résultat. Retirez un filtre pour élargir la recherche.</p>';
    renderPager($("#s-pager"), state.page, pages);
  }

  function simpleBars(container, rows, onSelect) {
    if (!rows?.length) { container.innerHTML = '<p class="empty-state">Aucune publication dans ce périmètre.</p>'; return; }
    const max = Math.max(...rows.map((row) => Number(row.count || 0)), 1);
    container.innerHTML = rows.map((row) => {
      const value = Number(row.count || 0);
      const name = row.label === UNKNOWN ? "Non déterminé" : row.label;
      const tag = onSelect ? "button" : "div";
      return `<${tag}${onSelect ? ' type="button"' : ""} class="metric-bar" data-label="${esc(row.label)}"${onSelect ? ` aria-label="Voir les ${value} incidents : ${esc(name)}"` : ""}><span class="metric-bar-label">${esc(name)}</span><span class="metric-bar-track" aria-hidden="true"><span style="width:${value === 0 ? 0 : (value / max) * 100}%"></span></span><strong>${formatNumber(value)}</strong></${tag}>`;
    }).join("");
    if (onSelect) $$("button.metric-bar", container).forEach((button) => button.addEventListener("click", () => onSelect(button.dataset.label)));
  }

  function renderDistribution(container, rows, onSelect) {
    const knownRows = rows.filter((row) => row.label !== UNKNOWN);
    const unknown = rows.find((row) => row.label === UNKNOWN);
    simpleBars(container, knownRows.slice(0, 6), onSelect);
    if (knownRows.length > 6) {
      const more = document.createElement("details");
      more.className = "distribution-more";
      more.innerHTML = `<summary>Autres catégories (${knownRows.length - 6})</summary><div></div>`;
      container.appendChild(more);
      simpleBars(more.querySelector("div"), knownRows.slice(6), onSelect);
    }
    if (unknown?.count) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "btn btn-link distribution-unknown";
      button.textContent = `${formatNumber(unknown.count)} non déterminé${unknown.count > 1 ? "s" : ""}`;
      button.addEventListener("click", () => onSelect(UNKNOWN));
      container.appendChild(button);
    }
  }

  function signalFilter(signal) {
    if (signal.dimension === "threat_sector") {
      const [threat, sector] = String(signal.label || "").split(" × ");
      return { threat: threat || "", sector: sector || "", period: String(signal.window_days || 30) };
    }
    if (["threat", "sector"].includes(signal.dimension)) return { [signal.dimension]: signal.label, period: String(signal.window_days || 30) };
    if (signal.dimension === "location") return { locations: [signal.label], period: String(signal.window_days || 30) };
    return { period: String(signal.window_days || 30) };
  }

  function signalHtml(signal) {
    const current = Number(signal.current || 0);
    const previous = Number(signal.previous || 0);
    return `<article class="signal-card"><strong>Hausse des incidents — ${esc(signal.label)}</strong><p>${current} publications sur ${signal.window_days} jours, contre ${previous} précédemment.</p><details><summary>Pourquoi ce signal ?</summary><p>Écart observé : +${formatNumber(signal.delta || 0)} publication${Number(signal.delta || 0) > 1 ? "s" : ""} entre deux périodes de ${signal.window_days} jours.</p></details><button type="button" class="btn btn-link" data-signal='${esc(JSON.stringify(signalFilter(signal)))}'>Voir les incidents →</button></article>`;
  }

  async function applySearchPatch(patch) {
    state.filters = { ...emptyFilters(), ...patch };
    state.page = 1;
    state.sort = "date-desc";
    state.view = "recherche";
    syncUrl(true);
    await ensureIncidents();
    populateSearchControls();
    render();
    window.scrollTo({ top: 0, behavior: "instant" });
  }

  function renderAnalyse() {
    $("#a-scope").value = state.analysisScope;
    $("#a-period").value = state.analysisPeriod;
    const a = state.status?.analytics;
    const profile = a?.scopes?.[state.analysisScope]?.[state.analysisPeriod];
    if (!profile) {
      $("#reading-line").textContent = "Analyse indisponible pour ce périmètre.";
      ["#chart-threat", "#chart-sector", "#signals-list", "#chart-evolution"].forEach((selector) => { $(selector).innerHTML = ""; });
      $("#monthly-card").hidden = $("#signals-card").hidden = true;
      return;
    }
    const period = state.analysisPeriod === "all" ? "Toute la base" : `${state.analysisPeriod} jours`;
    $("#reading-line").textContent = `${formatNumber(profile.incidents)} incidents retenus · ${formatNumber(profile.organisations)} organisations · ${period}${profile.undated ? ` · ${profile.undated} sans date` : ""}`;
    const meta = integrity();
    const complete = meta.known && meta.days >= (state.analysisPeriod === "all" ? Infinity : Number(state.analysisPeriod));
    const note = $("#analysis-coverage-note");
    note.hidden = complete;
    note.textContent = meta.known ? `Couverture continue : ${meta.days} jours. Ces répartitions décrivent les publications du corpus.` : "Couverture temporelle non établie. Ces répartitions décrivent les publications du corpus.";
    const patch = { locations: scopeLocations(state.analysisScope), period: state.analysisPeriod, admission: "ACCEPTED" };
    renderDistribution($("#chart-threat"), profile.threat || [], (label) => applySearchPatch({ ...patch, threat: label }));
    renderDistribution($("#chart-sector"), profile.sector || [], (label) => applySearchPatch({ ...patch, sector: label }));
    $("#monthly-card").hidden = !complete || (profile.months || []).length < 2;
    if (!$("#monthly-card").hidden) simpleBars($("#chart-evolution"), profile.months || []);
    const signals = trendsReady() && state.analysisScope === "all" && state.analysisPeriod === "30" ? (a.signals || []).filter((signal) => Number(signal.window_days) === 30).slice(0, 3) : [];
    $("#signals-card").hidden = !signals.length;
    $("#signals-list").innerHTML = signals.map(signalHtml).join("");
  }

  function renderSources() {
    const labels = { OK: "Disponible", PARTIAL: "Partielle", FAIL: "Indisponible", SKIPPED: "Non consultée" };
    $("#sources-detail-body").innerHTML = (state.status?.sources || []).map((source) => `<tr><th scope="row">${esc(sourceLabel(source.id))}</th><td><span class="source-state" data-status="${esc(source.status || "unknown")}">${esc(labels[source.status] || "État inconnu")}</span></td><td>${esc(formatDateTime(source.last_run))}</td><td>${source.status === "OK" ? "—" : esc(source.reason || "Couverture limitée.")}</td></tr>`).join("");
  }
  function productionMetric(label, value, detail, ok) {
    const status = ok === null ? "pending" : ok ? "ok" : "alert";
    return `<div class="production-metric" data-status="${status}"><small>${esc(label)}</small><strong>${esc(value)}</strong><span>${esc(detail)}</span></div>`;
  }

  function renderProduction() {
    const p = state.status?.production || {};
    const reliability = p.scheduled_reliability || {};
    const quality = p.quality || {};
    const targets = p.targets || {};
    const performance = p.performance || {};
    const observed = Number(reliability.observed || 0);
    const sector = Number(quality.sector_unknown_pct);
    const location = Number(quality.location_unknown_pct);
    const sectorKnown = sector >= 0;
    const locationKnown = location >= 0;
    const dedupValue = (key) => quality[key] === null || quality[key] === undefined
      ? "n.d."
      : formatNumber(quality[key]);
    const qualification = state.status?.qualification || {};
    const qualificationOk = qualification.state === "UNKNOWN" || !qualification.state
      ? null
      : qualification.state !== "PARTIAL";
    // La couverture sectorielle publiée (« Secteur inconnu ») et l'état
    // d'extraction sont deux lectures distinctes : un secteur peut être
    // classé par la référence alors que son couple activité/secteur reste
    // refusé, et l'inverse est vrai aussi.
    const pairs = qualification.pairs;
    const pairTotal = (key) => Number(pairs?.[key]?.total || 0);
    const pairsPending = pairs
      ? pairTotal("rejected") + pairTotal("rejected_exhausted") + pairTotal("technical_failure")
      : 0;
    const pairsDetail = pairs
      ? `${formatNumber(pairsPending)} en attente · ${formatNumber(pairTotal("abstained"))} abstention(s)`
      : "non disponible pour ce run";
    $("#production-metrics").innerHTML = [
      productionMetric(
        "Qualification",
        qualification.state || "n.d.",
        qualification.state === "PARTIAL"
          ? (qualification.reasons || []).join(" ; ")
          : "traitements nécessaires terminés",
        qualificationOk,
      ),
      productionMetric(
        "Couples activité/secteur",
        pairs ? `${formatNumber(pairTotal("accepted"))}/${formatNumber(Number(pairs.requested || 0))}` : "n.d.",
        pairsDetail,
        pairs ? pairsPending === 0 : null,
      ),
      productionMetric("Série planifiée", `${reliability.consecutive_successes || 0}/${reliability.required_consecutive_successes || 7}`, observed ? `${Number(reliability.success_rate_pct).toFixed(2)} % de succès observés` : "preuve en acquisition", observed ? Boolean(reliability.seven_run_proof_ready) : null),
      productionMetric("Secteur inconnu", sectorKnown ? `${sector.toFixed(2)} %` : "n.d.", `cible < ${targets.sector_unknown_pct || 20} %`, sectorKnown ? sector < Number(targets.sector_unknown_pct || 20) : null),
      productionMetric("Localisation inconnue", locationKnown ? `${location.toFixed(2)} %` : "n.d.", `cible < ${targets.location_unknown_pct || 5} %`, locationKnown ? location < Number(targets.location_unknown_pct || 5) : null),
      productionMetric("Doublons potentiellement manqués", dedupValue("missed_duplicate_candidate_pairs"), "paires encore séparées", null),
      productionMetric("Fusions faibles à vérifier", dedupValue("weak_merge_review_pairs"), "paires déjà regroupées", null),
      productionMetric("SAME non regroupés", dedupValue("validated_same_not_grouped_pairs"), "décisions validées", null),
      productionMetric("Paires en attente", dedupValue("pending_review_pairs"), "file de reprise", null),
      productionMetric("Corpus métier", `${Number(quality.corpus_false_positive_rate_pct || 0).toFixed(2)} % FP`, `${quality.corpus_false_negatives || 0} faux négatif · ${quality.dedup_known_false_merges || 0} faux merge`, Number(quality.corpus_false_positive_rate_pct || 0) === 0 && Number(quality.corpus_false_negatives || 0) === 0 && Number(quality.corpus_classification_errors || 0) === 0 && Number(quality.dedup_known_false_merges || 0) === 0),
      productionMetric("Dernier run", `${Number(performance.duration_seconds || 0).toFixed(1)} s`, `${performance.requests || 0} requêtes · ${performance.llm_calls || 0} appels LLM · $${Number(performance.llm_cost_usd || 0).toFixed(6)}`, null),
    ].join("");
  }

  async function ensureFacts() {
    if (state.facts) return state.facts;
    if (!factsPromise) factsPromise = loadJson("assets/data/facts.json", {});
    const facts = await factsPromise;
    if (state.loadErrors.has("assets/data/facts.json")) factsPromise = null;
    else state.facts = facts;
    return facts;
  }

  function incidentSummaryParagraphs(incident, detail) {
    const validDetail = detail && detail.version === 3;
    const raw = validDetail && Array.isArray(detail.summary_paragraphs) ? detail.summary_paragraphs.slice(0, 2).map((value) => String(value || "").trim()) : [];
    const generated = raw[0] && raw[0].length <= 1200 ? raw.filter((value) => known(value) && value.length <= 1200) : [];
    if (generated.length) return generated;
    const headline = cleanSummary((validDetail && detail.display_summary) || incident.summary);
    if (known(headline) && headline.length <= 1200) return [headline];
    return ["Synthèse indisponible."];
  }

  function regionalQualificationHtml(incident, detail) {
    const qualifications = Array.isArray(detail?.regional_watch) ? detail.regional_watch : [];
    if (!qualifications.length) return "";
    const candidate = incident.admission === "CANDIDATE";
    return `<section class="regional-qualification"><h3>Qualification de la veille régionale</h3>${qualifications.map((qualification) => {
      const score = Number.isInteger(qualification.score) && qualification.score >= 0 && qualification.score <= 100 ? `<p><strong>Score de confiance cyber : ${qualification.score}/100</strong></p><p class="qualification-context">${esc(qualification.score_definition || "Indicateur de confiance dans l’origine cyber du signal. Le score seul ne décide pas de son admission.")}</p>` : "";
      return `${score}${qualification.statut ? `<p><strong>${candidate ? "Incertitudes / état des preuves" : "État des preuves"}</strong> : ${esc(qualification.statut)}</p>` : ""}${qualification.admission_reason ? `<p><strong>${candidate ? "Éléments manquants / à confirmer" : "Motif de qualification"}</strong> : ${esc(qualification.admission_reason)}</p>` : ""}`;
    }).join("")}${candidate ? '<p class="qualification-context">Ce signal est exclu des statistiques des incidents retenus.</p>' : ""}</section>`;
  }

  async function openIncident(id, navigate = true) {
    const token = ++detailToken;
    state.incidentId = id;
    if (navigate) syncUrl(true);
    const dialog = $("#detail-dialog");
    $("#detail-dialog-content").innerHTML = '<h2 id="detail-dialog-title">Chargement de la fiche…</h2>';
    if (!dialog.open) dialog.showModal();
    let incident = state.latest.find((row) => row.id === id) || state.incidents.find((row) => row.id === id);
    if (!incident) {
      await ensureIncidents();
      incident = state.incidents.find((row) => row.id === id);
    }
    const facts = incident ? await ensureFacts() : {};
    if (token !== detailToken || state.incidentId !== id) return;
    if (!incident) {
      $("#detail-dialog-content").innerHTML = '<h2 id="detail-dialog-title">Incident introuvable</h2><p>Cette fiche n’est pas disponible dans le corpus publié.</p>';
    } else {
      const detail = facts[id];
      const meta = [incident.date ? formatDate(incident.date) : "Date non déterminée", threatLabel(incident), sectorLabel(incident) || "Secteur non déterminé"].filter(Boolean).join(" · ");
      const locationHtml = known(incident.location) ? `<p class="detail-location"><span class="incident-location${OCEAN_LOCATIONS.includes(incident.location) ? " incident-location-regional" : ""}">${esc(incident.location)}</span></p>` : "";
      const exposure = exposureLabel(incident);
      const paragraphs = incidentSummaryParagraphs(incident, detail);
      const qualificationHtml = regionalQualificationHtml(incident, detail);
      const candidateReason = qualificationHtml ? "" : esc(incident.admission_reason || "Publication en cours de vérification.");
      const candidate = incident.admission === "CANDIDATE" ? `<p class="candidate-note"><strong>À confirmer.</strong> ${candidateReason}</p>` : "";
      const websites = (incident.organisation_links || []).map(safeUrl).filter(Boolean);
      const websiteHtml = websites.length ? `<div class="organisation-sites"><span>Site de l’organisation</span>${websites.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>` : "";
      $("#detail-dialog-content").innerHTML = `<div class="detail-heading"><h2 id="detail-dialog-title">${esc(incident.org || "Organisation inconnue")}</h2>${locationHtml}<p class="detail-meta">${esc(meta)}</p>${candidate}${exposure ? `<p class="incident-exposure">${esc(exposure)}</p>` : ""}</div>
        <div class="detail-summary">${paragraphs.map((paragraph) => `<p>${esc(paragraph)}</p>`).join("")}</div>
        ${qualificationHtml}
        <div class="detail-sources"><h3>Publications</h3><div class="incident-source-badges">${sourceBadges(incident)}</div></div>${websiteHtml}`;
    }
    $("#detail-dialog-content").scrollTop = 0;
    $("#detail-dialog").scrollTop = 0;
    renderIntegrityAlert();
  }

  function openHealth(navigate = true) {
    state.diagnostic = true;
    if (navigate) syncUrl(true);
    renderSources();
    renderProduction();
    const meta = integrity();
    $("#health-context").textContent = `Dernière mise à jour : ${formatDateTime(state.status?.run?.as_of)} · ${meta.known ? `${meta.days} jours de couverture continue` : "Couverture temporelle non établie"}`;
    if (!$("#health-dialog").open) $("#health-dialog").showModal();
  }

  async function restoreDialogs() {
    if (!state.incidentId && $("#detail-dialog").open) $("#detail-dialog").close();
    if (!state.diagnostic && $("#health-dialog").open) $("#health-dialog").close();
    if (state.incidentId) await openIncident(state.incidentId, false);
    if (state.diagnostic) openHealth(false);
  }

  function bindGlobal() {
    $("#regional-candidates").addEventListener("click", () => applySearchPatch({ locations: focusLocations().slice(), admission: "CANDIDATE" }));
    $(".views").addEventListener("click", async (event) => {
      const button = event.target.closest("[data-view]");
      if (!button) return;
      state.view = button.dataset.view;
      state.page = 1;
      syncUrl(true);
      if (state.view === "recherche") { await ensureIncidents(); populateSearchControls(); }
      else if (state.view === "veille") await ensureIncidents();
      render();
    });
    document.addEventListener("click", (event) => {
      const open = event.target.closest("[data-open-id]");
      if (open) { if (window.getSelection()?.toString()) return; event.preventDefault(); openIncident(open.dataset.openId); return; }
      const signal = event.target.closest("[data-signal]");
      if (signal) { event.preventDefault(); try { applySearchPatch({ ...JSON.parse(signal.dataset.signal), admission: "ACCEPTED" }); } catch (_) {} }
    });
    document.addEventListener("keydown", (event) => {
      const card = event.target.closest(".incident-card[data-open-id]");
      if (card && ["Enter", " "].includes(event.key)) { event.preventDefault(); openIncident(card.dataset.openId); }
    });
    window.addEventListener("popstate", async () => {
      readUrl();
      if (state.view === "recherche") { await ensureIncidents(); populateSearchControls(); }
      else if (state.view === "veille") await ensureIncidents();
      render();
      await restoreDialogs();
    });
    $("#v-scope").addEventListener("change", (event) => { state.scope = event.target.value; state.veillePage = 1; syncUrl(); render(); });
    $("#veille-pager").addEventListener("click", (event) => {
      const button = event.target.closest("[data-page]");
      if (!button || button.disabled) return;
      state.veillePage += button.dataset.page === "next" ? 1 : -1;
      renderVeille(); syncUrl(true);
      $("#veille-title").focus({ preventScroll: true });
      $("#veille-title").scrollIntoView({ behavior: "instant", block: "start" });
    });
    ["scope", "period"].forEach((key) => $("#a-" + key).addEventListener("change", (event) => {
      if (key === "scope") state.analysisScope = event.target.value;
      else state.analysisPeriod = event.target.value;
      syncUrl(); renderAnalyse();
    }));
    $("#theme-toggle").addEventListener("click", () => {
      const dark = getComputedStyle(document.documentElement).colorScheme === "dark";
      const next = dark ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      writeStorage("localStorage", "cw-theme", next);
    });
    const savedTheme = readStorage("localStorage", "cw-theme");
    if (["light", "dark"].includes(savedTheme)) document.documentElement.dataset.theme = savedTheme;
    $("#run-pill").addEventListener("click", (event) => { event.preventDefault(); openHealth(); });
    ["detail", "health"].forEach((name) => {
      const dialog = $("#" + name + "-dialog");
      $("#" + name + "-close").addEventListener("click", () => dialog.close());
      dialog.addEventListener("click", (event) => {
        const rect = dialog.getBoundingClientRect();
        if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
      });
      dialog.addEventListener("close", () => {
        // Un popstate peut déjà avoir désigné une autre fiche : sa route gagne.
        if (name === "detail" && !state.incidentId || name === "health" && !state.diagnostic) return;
        if (name === "detail") { state.incidentId = ""; detailToken += 1; }
        else state.diagnostic = false;
        syncUrl();
      });
    });
  }

  function bindSearch() {
    let timer;
    const update = () => { state.page = 1; syncUrl(); renderRecherche(); };
    const closeLocations = (focus = false) => {
      $("#location-menu").hidden = true;
      $("#location-toggle").setAttribute("aria-expanded", "false");
      if (focus) $("#location-toggle").focus();
    };
    $(".search-bar").addEventListener("submit", (event) => event.preventDefault());
    $("#s-q").addEventListener("input", (event) => {
      state.filters.q = event.target.value;
      clearTimeout(timer);
      timer = setTimeout(update, 160);
    });
    ["threat", "sector", "source", "period", "admission"].forEach((key) => $("#s-" + key).addEventListener("change", (event) => { state.filters[key] = event.target.value; update(); }));
    $("#s-sort").addEventListener("change", (event) => { state.sort = event.target.value; update(); });
    $("#location-toggle").addEventListener("click", () => {
      const menu = $("#location-menu"); menu.hidden = !menu.hidden;
      $("#location-toggle").setAttribute("aria-expanded", String(!menu.hidden));
      if (!menu.hidden) $("#location-menu button").focus();
    });
    $("#location-close").addEventListener("click", () => closeLocations(true));
    document.addEventListener("click", (event) => { if (!event.target.closest(".location-picker")) closeLocations(); });
    document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("#location-menu").hidden) { event.preventDefault(); closeLocations(true); } });
    $("#s-locations").addEventListener("change", () => { state.filters.locations = $$("#s-locations input:checked").map((input) => input.value); update(); });
    $("#quick-focus").addEventListener("click", () => { state.filters.locations = focusLocations().slice(); update(); closeLocations(true); });
    $("#quick-ocean").addEventListener("click", () => { state.filters.locations = OCEAN_LOCATIONS.slice(); update(); closeLocations(true); });
    $("#s-active-filters").addEventListener("click", (event) => {
      const chip = event.target.closest("[data-remove-filter]");
      if (!chip) return;
      const key = chip.dataset.removeFilter;
      if (key === "locations") state.filters.locations = state.filters.locations.filter((value) => value !== chip.dataset.value);
      else state.filters[key] = key === "period" ? "all" : "";
      update();
      $("#s-q").focus();
    });
    $("#s-reset").addEventListener("click", () => { state.filters = emptyFilters(); state.sort = "date-desc"; update(); $("#s-q").focus(); });
    $("#s-pager").addEventListener("click", (event) => {
      const button = event.target.closest("[data-page]");
      if (!button || button.disabled) return;
      state.page += button.dataset.page === "next" ? 1 : -1;
      renderRecherche(); syncUrl(true);
      $("#s-count").focus({ preventScroll: true });
      $("#s-count").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function render() {
    $$(".views [data-view]").forEach((button) => button.setAttribute("aria-current", button.dataset.view === state.view ? "page" : "false"));
    $$(".view").forEach((view) => { view.hidden = view.id !== `view-${state.view}`; });
    if (state.view === "veille") renderVeille();
    else if (state.view === "recherche") renderRecherche();
    else renderAnalyse();
    renderIntegrityAlert();
    document.dispatchEvent(new CustomEvent("cyberwatch:render", { detail: { scope: state.scope } }));
  }

  async function init() {
    readUrl(); bindGlobal(); bindSearch();
    const [latest, status] = await Promise.all([loadJson("assets/data/latest.json", []), loadJson("assets/data/status.json", null)]);
    state.latest = Array.isArray(latest) ? latest : [];
    state.status = status;
    if (state.view === "recherche") { await ensureIncidents(); populateSearchControls(); }
    else if (state.view === "veille") await ensureIncidents();
    renderHeader(); render();
    document.body.dataset.dashboardReady = "true";
    await restoreDialogs();
    window.setInterval(() => { renderHeader(); renderIntegrityAlert(); }, 5 * 60 * 1000);
  }

  init();
})();
