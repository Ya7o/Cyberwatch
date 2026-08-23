/* Cyberwatch dashboard v2 — rendu des données canoniques, sans arbitrage métier. */
(() => {
  "use strict";

  const DAY = 864e5;
  const PAGE_SIZE = 30;
  const UNKNOWN = "Inconnu";
  const OCEAN_LOCATIONS = ["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"];
  const FOCUS_LOCATIONS = ["La Réunion", "Mayotte"];
  const SOURCE_LABELS = {
    RANSOMWARE_LIVE: "Ransomware.live",
    CYBERATTAQUE_ORG: "Cyberattaque.org",
    FRENCHBREACHES: "FrenchBreaches",
    BONJOURLAFUITE: "BonjourLaFuite",
    VEILLE_LLM: "Veille locale Réunion / Mayotte",
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const normalize = (value) => String(value ?? "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  const sourceLabel = (id) => SOURCE_LABELS[id] || id || "Source";
  const known = (value) => Boolean(String(value ?? "").trim()) && String(value).trim() !== UNKNOWN;
  const unique = (values) => Array.from(new Set(values.filter(known)));
  const formatNumber = (value) => new Intl.NumberFormat("fr-FR").format(Number(value));
  const formatDate = (value) => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric" }).format(date) : "—";
  };
  const formatDateTime = (value) => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date) : "—";
  };
  const safeUrl = (value) => {
    try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.href : ""; }
    catch (_) { return ""; }
  };
  const host = (value) => { try { return new URL(value).hostname.replace(/^www\./, ""); } catch (_) { return "Source"; } };
  const cleanSummary = (value) => String(value || "")
    .replace(/^Éléments documentés\s*:\s*/i, "")
    .replace(/^Impact documenté\s*:\s*/i, "")
    .replace(/\s*;\s*données concernées\s*:\s*/i, ". Données exposées : ")
    .replace(/\s+/g, " ").trim();

  const state = {
    view: "veille",
    latest: [],
    incidents: [],
    incidentsLoaded: false,
    facts: null,
    status: null,
    filters: { q: "", threat: "", sector: "", locations: [], source: "", period: "all" },
    sort: "date-desc",
    page: 1, pageSize: Number(sessionStorage.getItem("cw-page-size")) || PAGE_SIZE,
  };

  async function loadJson(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) throw new Error(`${response.status}`);
      return await response.json();
    } catch (error) {
      console.error(`Cyberwatch: échec de chargement ${path}`, error);
      return fallback;
    }
  }

  function readUrl() {
    const params = new URLSearchParams(location.search);
    state.view = ["veille", "recherche", "analyse"].includes(params.get("vue")) ? params.get("vue") : "veille";
    state.filters.q = params.get("q") || "";
    state.filters.threat = params.get("threat") || "";
    state.filters.sector = params.get("sector") || "";
    state.filters.locations = unique(params.getAll("location"));
    state.filters.source = params.get("source") || "";
    state.filters.period = params.get("period") || "all";
    state.sort = params.get("sort") || "date-desc";
    state.page = Math.max(1, Number(params.get("page")) || 1);
  }

  function syncUrl(push = false) {
    const params = new URLSearchParams();
    if (state.view !== "veille") params.set("vue", state.view);
    if (state.view === "recherche") {
      if (state.filters.q) params.set("q", state.filters.q);
      if (state.filters.threat) params.set("threat", state.filters.threat);
      if (state.filters.sector) params.set("sector", state.filters.sector);
      state.filters.locations.forEach((value) => params.append("location", value));
      if (state.filters.source) params.set("source", state.filters.source);
      if (state.filters.period !== "all") params.set("period", state.filters.period);
      if (state.sort !== "date-desc") params.set("sort", state.sort);
      if (state.page > 1) params.set("page", String(state.page));
    }
    const query = params.toString();
    const url = `${location.pathname}${query ? `?${query}` : ""}`;
    if (push) history.pushState(null, "", url); else history.replaceState(null, "", url);
  }

  function sourceBadges(incident) {
    const direct = new Map((incident.source_links || []).map((link) => [link.source, safeUrl(link.url)]));
    return unique(incident.sources || []).sort((a, b) => sourceLabel(a).localeCompare(sourceLabel(b), "fr")).map((id) => {
      const url = direct.get(id);
      return url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(sourceLabel(id))}</a>` : `<span>${esc(sourceLabel(id))}</span>`;
    }).join("");
  }

  function sectorTentativeChip(incident) {
    if (known(incident.sector) || !known(incident.sector_tentative)) return "";
    return `<span class="chip" data-status="PARTIAL">${esc(incident.sector_tentative)} (supposé, non confirmé)</span>`;
  }

  function incidentCardHtml(incident) {
    const tags = [incident.threat, incident.sector].filter(known).map((value) => `<span>${esc(value)}</span>`).join("") + (incident.sensitive_data_exposed ? `<span data-status="PARTIAL">Données sensibles</span>` : "") + sectorTentativeChip(incident);
    const summary = cleanSummary(incident.summary);
    return `<article class="incident-card" data-id="${esc(incident.id)}">
      <div class="incident-main">
        <div class="incident-card-top"><time datetime="${esc(incident.date)}">${esc(formatDate(incident.date))}</time>${known(incident.location) ? `<span>${esc(incident.location)}</span>` : ""}</div>
        <button type="button" class="incident-org-link" data-open-id="${esc(incident.id)}">${esc(incident.org || "Organisation inconnue")}</button>
        ${tags ? `<p class="incident-tags">${tags}</p>` : ""}
        ${summary ? `<p class="incident-summary-text">${esc(summary)}</p>` : ""}
      </div>
      <div class="incident-side">
        <div class="incident-source-badges">${sourceBadges(incident)}</div>
        <button type="button" class="btn btn-primary" data-open-id="${esc(incident.id)}">Voir le détail</button>
      </div>
    </article>`;
  }

  function signalTitle(signal) {
    if (signal.kind === "new_pair") return `Nouveau signal : ${signal.label}`;
    if (signal.kind === "emerging") return `${signal.label} apparaît dans la période récente`;
    return `Hausse des incidents — ${signal.label}`;
  }

  function signalSummary(signal) {
    if (signal.previous === 0) return `${signal.current} incidents sur ${signal.window_days} jours, contre aucun sur la période précédente.`;
    return `${signal.current} incidents sur ${signal.window_days} jours, contre ${signal.previous} sur les ${signal.window_days} jours précédents.`;
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

  function signalHtml(signal, compact = false) {
    const evidence = (signal.incident_ids || []).slice(0, 5).map((id) => state.latest.find((row) => row.id === id) || state.incidents.find((row) => row.id === id)).filter(Boolean);
    const detail = evidence.length ? `<ul>${evidence.map((row) => `<li>${esc(formatDate(row.date))} — ${esc(row.org || "Organisation inconnue")}${known(row.threat) ? ` · ${esc(row.threat)}` : ""}</li>`).join("")}</ul>` : "";
    return `<article class="signal-card ${compact ? "signal-card--compact" : ""}">
      <div class="signal-card-head"><span class="trend-arrow" aria-hidden="true">↑</span><div><strong>${esc(signalTitle(signal))}</strong><p>${esc(signalSummary(signal))}</p></div></div>
      ${compact ? "" : `<details><summary>Pourquoi ce signal ?</summary><div class="signal-why"><p>Écart observé : +${formatNumber(signal.delta || 0)} incident${Number(signal.delta || 0) > 1 ? "s" : ""} par rapport à la période précédente.</p>${detail}</div></details>`}
      <button type="button" class="btn btn-link" data-signal='${esc(JSON.stringify(signalFilter(signal)))}'>Voir les incidents →</button>
    </article>`;
  }

  function renderHeader() {
    const counts = state.status?.counts || {};
    const sources = state.status?.sources || [];
    const total = sources.length || [counts.ok, counts.partial, counts.fail, counts.skipped].reduce((sum, value) => sum + Number(value || 0), 0);
    const ok = Number(counts.ok || 0);
    const run = state.status?.run || {};
    $("#run-pill-text").textContent = total ? `${ok}/${total} sources · ${formatDateTime(run.as_of)}` : "État des sources indisponible";
    $("#run-pill").dataset.status = total && ok === total ? "ok" : "degraded";
  }

  function renderVeille() {
    const signal = state.status?.analytics?.signals?.[0];
    $("#veille-signal").innerHTML = signal ? signalHtml(signal, true) : "";
    const local = state.latest.filter((row) => FOCUS_LOCATIONS.includes(row.location));
    $("#focus-body").innerHTML = local.length
      ? `<p class="status-bubble status-bubble--active"><strong>${local.length}</strong> incident${local.length > 1 ? "s" : ""} à La Réunion / Mayotte sur les 30 derniers jours.</p><div class="focus-list">${local.map(incidentCardHtml).join("")}</div>`
      : '<p class="status-bubble status-bubble--quiet">Aucun incident à La Réunion / Mayotte sur les 30 derniers jours.</p>';
    $("#veille-count").textContent = state.latest.length ? `${formatNumber(state.latest.length)} incidents` : "Aucun incident";
    $("#veille-list").innerHTML = state.latest.length ? state.latest.map(incidentCardHtml).join("") : '<p class="empty-state">Aucun incident sur les 30 derniers jours.</p>';
  }

  function optionHtml(values, current, allLabel) {
    return `<option value="">${esc(allLabel)}</option>` + values.map((value) => `<option value="${esc(value)}" ${value === current ? "selected" : ""}>${esc(value)}</option>`).join("");
  }

  function populateSearchControls() {
    const rows = state.incidents;
    const withUnknown = (values) => Array.from(new Set(values.map((value) => String(value || UNKNOWN).trim() || UNKNOWN))).sort((a, b) => a.localeCompare(b, "fr"));
    const threats = withUnknown(rows.map((row) => row.threat));
    const sectors = withUnknown(rows.map((row) => row.sector));
    const locations = withUnknown(rows.map((row) => row.location));
    const sources = unique(rows.flatMap((row) => row.sources || [])).sort((a, b) => sourceLabel(a).localeCompare(sourceLabel(b), "fr"));
    $("#s-threat").innerHTML = optionHtml(threats, state.filters.threat, "Toutes");
    $("#s-sector").innerHTML = optionHtml(sectors, state.filters.sector, "Tous");
    $("#s-source").innerHTML = `<option value="">Toutes</option>` + sources.map((value) => `<option value="${esc(value)}" ${value === state.filters.source ? "selected" : ""}>${esc(sourceLabel(value))}</option>`).join("");
    $("#s-locations").innerHTML = locations.map((value) => `<label><input type="checkbox" value="${esc(value)}" ${state.filters.locations.includes(value) ? "checked" : ""}> <span>${esc(value)}</span></label>`).join("");
    $("#s-q").value = state.filters.q;
    $("#s-period").value = state.filters.period;
    $("#s-sort").value = state.sort;
    $("#s-page-size").value = String(state.pageSize);
    updateLocationSummary();
  }

  function updateLocationSummary() {
    const count = state.filters.locations.length;
    $("#location-toggle").textContent = count ? `${count} territoire${count > 1 ? "s" : ""} sélectionné${count > 1 ? "s" : ""}` : "Tous les territoires";
  }

  function cutoffFor(period) {
    const days = Number(period);
    return Number.isFinite(days) && days > 0 ? new Date(Date.now() - days * DAY) : null;
  }

  function filteredSearch() {
    const query = normalize(state.filters.q);
    const cutoff = cutoffFor(state.filters.period);
    return state.incidents.filter((incident) => {
      const searchText = normalize([incident.org, incident.threat, incident.sector, incident.location, incident.summary, ...(incident.sources || []).map(sourceLabel)].join(" "));
      if (query && !searchText.includes(query)) return false;
      if (state.filters.threat && String(incident.threat || UNKNOWN) !== state.filters.threat) return false;
      if (state.filters.sector && String(incident.sector || UNKNOWN) !== state.filters.sector) return false;
      if (state.filters.locations.length && !state.filters.locations.includes(String(incident.location || UNKNOWN))) return false;
      if (state.filters.source && !(incident.sources || []).includes(state.filters.source)) return false;
      if (cutoff) {
        const date = new Date(incident.date);
        if (Number.isNaN(date.getTime()) || date < cutoff) return false;
      }
      return true;
    });
  }

  function sortedSearch(rows) {
    const result = rows.slice();
    if (state.sort === "date-asc") return result.sort((a, b) => String(a.date).localeCompare(String(b.date)));
    if (state.sort === "org") return result.sort((a, b) => String(a.org || "").localeCompare(String(b.org || ""), "fr"));
    return result.sort((a, b) => String(b.date).localeCompare(String(a.date)));
  }

  function renderActiveFilters() {
    const labels = [];
    if (state.filters.q) labels.push(`Recherche : “${state.filters.q}”`);
    if (state.filters.threat) labels.push(`Menace : ${state.filters.threat}`);
    if (state.filters.sector) labels.push(`Secteur : ${state.filters.sector}`);
    state.filters.locations.forEach((value) => labels.push(`Territoire : ${value}`));
    if (state.filters.source) labels.push(`Source : ${sourceLabel(state.filters.source)}`);
    if (state.filters.period !== "all") labels.push(`Période : ${state.filters.period} jours`);
    $("#s-active-filters").innerHTML = labels.map((label) => `<span>${esc(label)}</span>`).join("");
  }

  function renderRecherche() {
    if (!state.incidentsLoaded) return;
    populateSearchControls();
    renderActiveFilters();
    const rows = sortedSearch(filteredSearch());
    const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * state.pageSize;
    const shown = rows.slice(start, start + state.pageSize);
    $("#s-count").textContent = `${formatNumber(rows.length)} incident${rows.length > 1 ? "s" : ""}`;
    $("#s-list").innerHTML = shown.length ? shown.map(incidentCardHtml).join("") : '<p class="empty-state">Aucun résultat.</p>';
    $("#s-pager").innerHTML = `<button type="button" class="btn" data-page="prev" ${state.page <= 1 ? "disabled" : ""}>← Précédent</button><span>${state.page} / ${pages}</span><button type="button" class="btn" data-page="next" ${state.page >= pages ? "disabled" : ""}>Suivant →</button>`;
  }

  function simpleBars(container, rows, onSelect) {
    if (!container) return;
    if (!rows?.length) { container.innerHTML = '<p class="empty-state">Aucune donnée.</p>'; return; }
    const max = Math.max(...rows.map((row) => Number(row.count ?? row.value ?? 0)), 1);
    container.innerHTML = rows.slice(0, 10).map((row) => {
      const value = Number(row.count ?? row.value ?? 0);
      const width = Math.max(2, Math.round((value / max) * 100));
      return `<button type="button" class="metric-bar" data-label="${esc(row.label)}"><span class="metric-bar-label">${esc(row.label)}</span><span class="metric-bar-track"><span style="width:${width}%"></span></span><strong>${formatNumber(value)}</strong></button>`;
    }).join("");
    if (onSelect) $$(".metric-bar", container).forEach((button) => button.addEventListener("click", () => onSelect(button.dataset.label)));
  }

  function renderMonthly(series) {
    const container = $("#chart-evolution");
    if (!series?.months?.length) { container.innerHTML = '<p class="empty-state">Aucune donnée.</p>'; return; }
    simpleBars(container, series.months.map((month, index) => ({ label: month, count: series.total[index] })).slice(-12));
  }

  function oceanProfileHtml(profile, label) {
    if (!profile?.incidents) return `<p><strong>${esc(label)}</strong> — aucun incident observé.</p>`;
    const threats = (profile.threats || []).slice(0, 3).map((row) => `${row.label} (${row.count})`).join(" · ");
    return `<div class="ocean-profile"><strong>${esc(label)}</strong><span>${formatNumber(profile.incidents)} incidents</span>${threats ? `<small>${esc(threats)}</small>` : ""}</div>`;
  }

  function renderSources() {
    $("#sources-leds").innerHTML = (state.status?.sources || []).map((source) => `<div class="source-status"><span class="source-dot" data-status="${esc(source.status || "unknown")}"></span><strong>${esc(sourceLabel(source.id))}</strong><small>${esc(source.status || "—")}</small></div>`).join("");
    $("#sources-detail-body").innerHTML = (state.status?.sources || []).map((source) => `<tr><td>${esc(sourceLabel(source.id))}</td><td>${esc(source.status || "—")}</td><td>${esc(formatDateTime(source.last_run))}</td><td>${esc(source.duration ? `${source.duration} s` : "—")}</td><td>${esc(formatNumber(source.items_collected || source.items || 0))}</td><td>${esc(source.reason || source.comment || "—")}</td></tr>`).join("");
  }

  function applySearchPatch(patch) {
    state.filters = { q: "", threat: "", sector: "", locations: [], source: "", period: "all", ...state.filters, ...patch };
    state.page = 1;
    state.view = "recherche";
    syncUrl(true);
    render();
  }

  function renderAnalyse() {
    const a = state.status?.analytics;
    if (!a) { $("#analysis-content").innerHTML = '<p class="empty-state">Analyse indisponible.</p>'; return; }
    const q = a.quality || {};
    $("#reading-line").innerHTML = `<strong>${formatNumber(q.incidents || a.dated_incidents || 0)}</strong> incidents · <strong>${formatNumber(q.organisations || 0)}</strong> organisations · ${esc(formatDate(q.first_date))} → ${esc(formatDate(q.last_date))}`;
    renderMonthly(a.series);
    simpleBars($("#chart-threat"), a.top_90d?.threat || [], (label) => applySearchPatch({ threat: label, period: "90" }));
    const sectorRows = (a.top_90d?.sector || []).filter((row) => row.label !== UNKNOWN);
    const sectorUnknown = (a.top_90d?.sector || []).find((row) => row.label === UNKNOWN)?.count || 0;
    simpleBars($("#chart-sector"), sectorRows, (label) => applySearchPatch({ sector: label, period: "90" }));
    $("#chart-sector").insertAdjacentHTML("beforeend", `<p class="hint">Secteur non renseigné : ${formatNumber(sectorUnknown)} incident${sectorUnknown > 1 ? "s" : ""}</p>`);
    $("#signals-list").innerHTML = (a.signals || []).slice(0, 12).map((signal) => signalHtml(signal)).join("") || '<p class="empty-state">Aucun signal notable sur la période.</p>';
    $("#ocean-focus").innerHTML = oceanProfileHtml(a.focus?.profile, "La Réunion / Mayotte");
    $("#ocean-ensemble").innerHTML = oceanProfileHtml(a.ocean?.profile, "Ensemble Océan Indien");
    $("#ocean-focus").onclick = () => applySearchPatch({ locations: FOCUS_LOCATIONS.slice() });
    $("#ocean-ensemble").onclick = () => applySearchPatch({ locations: OCEAN_LOCATIONS.slice() });
    renderSources();
  }

  async function ensureFacts() {
    if (state.facts) return state.facts;
    state.facts = await loadJson("assets/data/facts.json", {});
    return state.facts;
  }

  function detailField(label, content) {
    if (!content || (Array.isArray(content) && !content.length)) return "";
    const rendered = Array.isArray(content) ? content.map((item) => `<span class="detail-chip">${esc(item)}</span>`).join("") : esc(content);
    return `<div class="resolved-field"><dt>${esc(label)}</dt><dd>${rendered}</dd></div>`;
  }

  // Regroupement par famille et code couleur de sensibilité des données
  // compromises, calculés par règles déterministes côté client — jamais par
  // le LLM (§ Identité hors LLM, CLAUDE.md).
  const DATA_TYPE_FAMILY_ORDER = ["Identité", "Coordonnées", "Financières", "Authentification", "Santé", "Professionnelles", "Administratives", "Autres"];
  // Certains libellés canoniques sont au pluriel avec la marque du pluriel
  // sur le premier mot ("mots de passe", "cartes de paiement", "pièces
  // d'identité") : une simple sous-chaîne au singulier ne les retrouve pas
  // (« mots » ne contient pas « mot »). Les deux formes sont donc listées
  // explicitement plutôt que de deviner un radical.
  const DATA_TYPE_FAMILY_RULES = [
    ["Santé", ["sante", "medical", "medic", "patient", "diagnostic", "patholog", "ordonnance", "traitement", "vaccin"]],
    ["Financières", ["iban", "rib", "bancair", "carte de paiement", "cartes de paiement", "carte bancaire", "cartes bancaires", "paiement", "transaction", "financement", "factur", "revenu", "salaire", "patrimoine"]],
    ["Authentification", ["mot de passe", "mots de passe", "password", "hash", "identifiant", "login", "token", "authent", "cle api", "secret", "otp"]],
    ["Administratives", ["nir", "securite sociale", "passeport", "carte d identite", "cartes d identite", "piece d identite", "pieces d identite", "permis de conduire", "acte de naissance", "justificatif de domicile", "immatriculation", "siret", "siren"]],
    ["Professionnelles", ["certification", "qualification", "experience", "evaluation", "formation", "parcours professionnel", "emploi", "poste", "metier", "profession", "employeur"]],
    ["Identité", ["nom", "prenom", "genre", "civilite", "photo", "selfie", "biometr", "nationalite"]],
    ["Coordonnées", ["mail", "adresse", "telephone", "mobile", "departement", "pays", "ville", "code postal", "numero client", "identifiant client", "date de naissance", "naissance"]],
  ];
  const SENSITIVITY_CRITICAL_MARKERS = ["mot de passe", "mots de passe", "password", "hash", "token", "otp", "secret", "cle api", "authent", "sante", "medical", "patient", "diagnostic", "patholog", "ordonnance", "traitement", "vaccin", "nir", "securite sociale", "passeport", "carte d identite", "cartes d identite", "piece d identite", "pieces d identite", "permis de conduire", "biometr", "selfie"];
  const SENSITIVITY_HIGH_MARKERS = ["iban", "rib", "bancair", "carte de paiement", "cartes de paiement", "carte bancaire", "cartes bancaires", "releve de compte", "revenu", "salaire", "patrimoine"];
  const SENSITIVITY_MODERATE_MARKERS = ["mail", "telephone", "mobile", "adresse", "numero client", "identifiant client", "date de naissance", "naissance"];

  function dataTypeFamily(value) {
    const normalized = normalize(value);
    for (const [label, keywords] of DATA_TYPE_FAMILY_RULES) {
      if (keywords.some((keyword) => normalized.includes(keyword))) return label;
    }
    return "Autres";
  }

  function dataTypeSensitivity(value) {
    const normalized = normalize(value);
    if (SENSITIVITY_CRITICAL_MARKERS.some((marker) => normalized.includes(marker))) return "critical";
    if (SENSITIVITY_HIGH_MARKERS.some((marker) => normalized.includes(marker))) return "high";
    if (SENSITIVITY_MODERATE_MARKERS.some((marker) => normalized.includes(marker))) return "moderate";
    return "";
  }

  function dataTypesHtml(entries) {
    const values = entries.map((entry) => entry.value).filter(known);
    if (!values.length) return "";
    const groups = new Map(DATA_TYPE_FAMILY_ORDER.map((label) => [label, []]));
    const seen = new Set();
    values.forEach((value) => {
      const cleaned = String(value).trim();
      if (!cleaned || seen.has(cleaned)) return;
      seen.add(cleaned);
      groups.get(dataTypeFamily(cleaned)).push(cleaned);
    });
    const rendered = DATA_TYPE_FAMILY_ORDER.map((label) => {
      const items = groups.get(label) || [];
      if (!items.length) return "";
      const chips = items.map((value) => {
        const tier = dataTypeSensitivity(value);
        const tierClass = tier ? ` incident-data-value--sensitivity-${tier}` : "";
        return `<span class="incident-data-value${tierClass}">${esc(value)}</span>`;
      }).join("");
      return `<details class="incident-data-group"><summary>${esc(label)} · ${items.length}</summary><div class="incident-data-values">${chips}</div></details>`;
    }).filter(Boolean).join("");
    return `<div class="incident-data-types"><div class="incident-data-types-title">Données exposées :</div>${rendered}</div>`;
  }

  function unitLabel(value) {
    return ({ people: "personnes", accounts: "comptes", users: "utilisateurs", clients: "clients", records: "enregistrements", files: "fichiers" })[value] || value || "";
  }

  function affectedHtml(records) {
    if (!Array.isArray(records) || !records.length) return "";
    const values = records.map((record) => {
      const raw = record.raw || "";
      let value = raw || `${formatNumber(record.value)} ${unitLabel(record.unit)}`.trim();
      if (record.semantic === "unique" && record.unit === "records" && !raw) value = `${formatNumber(record.value)} enregistrements uniques`;
      return value;
    });
    return detailField("Volume documenté", values);
  }

  async function openIncident(id) {
    const incident = state.latest.find((row) => row.id === id) || state.incidents.find((row) => row.id === id);
    if (!incident) return;
    const facts = await ensureFacts();
    const detail = facts[id];
    const sourceLinks = unique(incident.urls || []).map(safeUrl).filter(Boolean);
    const meta = [incident.date ? formatDate(incident.date) : "", incident.threat, incident.sector, incident.location].filter(known).join(" · ");
    const validDetail = detail && detail.version === 2;
    const fields = validDetail ? detail.fields || {} : {};
    const values = validDetail ? [
      affectedHtml(detail.affected || []),
      dataTypesHtml(detail.data_types || []),
      detailField("Acteur", fields.threat_actor?.value),
      detailField("Tiers impliqué", fields.third_party?.value),
      detailField("Vecteur d’entrée", CW.initialAccessLabel(fields.initial_access?.value)),
      detailField("Localisation précise", fields.fine_location?.value),
      detailField("Vulnérabilités", (detail.vulnerabilities || []).map((entry) => entry.value).filter(known)),
      detailField("Date de l’attaque", fields.attack_date?.value ? formatDate(fields.attack_date.value) : ""),
      detailField("Découverte", fields.discovered_date?.value ? formatDate(fields.discovered_date.value) : ""),
      detailField("CVSS", fields.cvss?.value),
      detailField("Volume de données", fields.data_volume?.value),
      detailField("Impact", fields.impact?.value),
      detailField("Évolution", fields.evolution?.value),
      detailField("Systèmes concernés", (detail.systems || []).map((entry) => entry.value).filter(known)),
      detailField("Périmètres de données", (detail.datasets || []).map((entry) => entry.value).filter(known)),
    ].filter(Boolean).join("") : "";
    const summary = cleanSummary((validDetail && detail.display_summary) || incident.summary);
    const tentativeChip = sectorTentativeChip(incident);
    $("#detail-dialog-content").innerHTML = `<div class="detail-heading"><h2 id="detail-dialog-title">${esc(incident.org || "Organisation inconnue")}</h2>${meta ? `<p>${esc(meta)}</p>` : ""}${tentativeChip ? `<p>${tentativeChip}</p>` : ""}</div>
      ${summary ? `<p class="detail-summary">${esc(summary)}</p>` : ""}
      <section class="resolved-facts"><h3>Éléments documentés</h3>${values || '<p class="empty-state">Aucun élément structuré supplémentaire.</p>'}</section>
      <div class="detail-sources"><strong>Sources</strong><div class="incident-source-badges">${sourceBadges(incident)}</div></div>`;
    $("#detail-dialog").showModal();
  }

  function bindGlobal() {
    $(".views").addEventListener("click", (event) => {
      const button = event.target.closest("[data-view]");
      if (!button) return;
      state.view = button.dataset.view;
      state.page = 1;
      syncUrl(true);
      render();
    });
    document.addEventListener("click", (event) => {
      const open = event.target.closest("[data-open-id]");
      if (open) { event.preventDefault(); openIncident(open.dataset.openId); return; }
      const signal = event.target.closest("[data-signal]");
      if (signal) { event.preventDefault(); try { applySearchPatch(JSON.parse(signal.dataset.signal)); } catch (_) {} }
    });
    window.addEventListener("popstate", () => { readUrl(); render(); });
    $("#theme-toggle").addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("cw-theme", next);
    });
    const savedTheme = localStorage.getItem("cw-theme");
    if (savedTheme) document.documentElement.dataset.theme = savedTheme;
    $("#run-pill").addEventListener("click", (event) => { event.preventDefault(); state.view = "analyse"; syncUrl(true); render(); requestAnimationFrame(() => $("#sources")?.scrollIntoView({ behavior: "smooth" })); });
    $("#detail-dialog").addEventListener("click", (event) => { if (event.target === $("#detail-dialog")) $("#detail-dialog").close(); });
    document.addEventListener("keydown", (event) => { if (event.key === "Escape" && $("#detail-dialog").open) $("#detail-dialog").close(); });
  }

  function bindSearch() {
    let timer;
    $("#s-q").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => { state.filters.q = event.target.value; state.page = 1; syncUrl(); renderRecherche(); }, 160);
    });
    ["threat", "sector", "source", "period"].forEach((key) => $("#s-" + key).addEventListener("change", (event) => {
      state.filters[key] = event.target.value; state.page = 1; syncUrl(); renderRecherche();
    }));
    $("#s-sort").addEventListener("change", (event) => { state.sort = event.target.value; state.page = 1; syncUrl(); renderRecherche(); });
    $("#s-page-size").addEventListener("change", (event) => { state.pageSize = Number(event.target.value) || PAGE_SIZE; sessionStorage.setItem("cw-page-size", String(state.pageSize)); state.page = 1; renderRecherche(); });
    const closeLocations = () => { $("#location-menu").hidden = true; $("#location-toggle").setAttribute("aria-expanded", "false"); };
    $("#location-toggle").addEventListener("click", () => { const menu = $("#location-menu"); menu.hidden = !menu.hidden; $("#location-toggle").setAttribute("aria-expanded", String(!menu.hidden)); });
    $("#location-close").addEventListener("click", closeLocations);
    document.addEventListener("click", (event) => { if (!event.target.closest(".location-picker")) closeLocations(); });
    $("#s-locations").addEventListener("change", () => {
      state.filters.locations = $$("input:checked", $("#s-locations")).map((input) => input.value);
      state.page = 1; updateLocationSummary(); syncUrl(); renderRecherche();
    });
    $("#quick-focus").addEventListener("click", () => { state.filters.locations = FOCUS_LOCATIONS.slice(); state.page = 1; syncUrl(); renderRecherche(); });
    $("#quick-ocean").addEventListener("click", () => { state.filters.locations = OCEAN_LOCATIONS.slice(); state.page = 1; syncUrl(); renderRecherche(); });
    $("#s-reset").addEventListener("click", () => {
      state.filters = { q: "", threat: "", sector: "", locations: [], source: "", period: "all" }; state.sort = "date-desc"; state.page = 1; syncUrl(); renderRecherche();
    });
    $("#s-pager").addEventListener("click", (event) => {
      const button = event.target.closest("[data-page]");
      if (!button) return;
      state.page += button.dataset.page === "next" ? 1 : -1;
      syncUrl(); renderRecherche(); window.scrollTo({ top: $("#s-count").offsetTop - 90, behavior: "smooth" });
    });
  }

  function render() {
    $$(".views [data-view]").forEach((button) => button.setAttribute("aria-current", String(button.dataset.view === state.view)));
    $$(".view").forEach((view) => { view.hidden = view.id !== `view-${state.view}`; });
    if (state.view === "veille") renderVeille();
    else if (state.view === "recherche") renderRecherche();
    else renderAnalyse();
  }

  async function init() {
    readUrl();
    bindGlobal();
    bindSearch();
    const [latest, status, incidents] = await Promise.all([
      loadJson("assets/data/latest.json", []),
      loadJson("assets/data/status.json", null),
      loadJson("assets/data/incidents.json", []),
    ]);
    state.latest = Array.isArray(latest) ? latest : [];
    state.status = status;
    state.incidents = Array.isArray(incidents) ? incidents : [];
    state.incidentsLoaded = true;
    renderHeader();
    render();
  }

  init();
})();
