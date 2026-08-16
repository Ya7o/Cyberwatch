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
  const DATA_TYPE_GROUP_ORDER = [
    "Identité & coordonnées",
    "Profession / formation",
    "Finance & transactions",
    "Santé",
    "Accès & authentification",
    "Autres",
  ];
  const DATA_TYPE_GROUP_RULES = [
    ["Santé", ["sante", "medical", "medic", "patient", "diagnostic", "patholog", "ordonnance", "traitement", "vaccin"]],
    ["Finance & transactions", ["iban", "rib", "bancair", "carte de paiement", "carte bancaire", "paiement", "transaction", "financement", "factur", "revenu", "salaire"]],
    ["Accès & authentification", ["mot de passe", "password", "hash", "identifiant", "login", "token", "authent", "cle api", "secret", "otp"]],
    ["Profession / formation", ["certification", "qualification", "experience", "evaluation", "formation", "parcours professionnel", "emploi", "poste", "metier", "profession"]],
    ["Identité & coordonnées", ["nom", "prenom", "genre", "email", "e-mail", "adresse", "telephone", "mobile", "naissance", "nationalite", "departement", "pays", "ville", "identite", "numero client"]],
  ];
  const orgKey = (value) => String(value || "").trim().toLocaleLowerCase("fr-FR");
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
      VEILLE_LLM: "veillellmReYt",
      CERT_MU_ALERTS: "CERT-MU",
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

  function formatNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString("fr-FR") : String(value || "");
  }

  function normalizedDataType(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase("fr-FR");
  }

  function dataTypeGroup(value) {
    const normalized = normalizedDataType(value);
    for (const [label, keywords] of DATA_TYPE_GROUP_RULES) {
      if (keywords.some((keyword) => normalized.includes(keyword))) return label;
    }
    return "Autres";
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
      .sources-detail{margin-top:14px}.sources-detail>summary{cursor:pointer;font-size:13px;color:var(--text-secondary);list-style:none}.sources-detail>summary::-webkit-details-marker{display:none}.sources-detail>summary::before{content:"▸";color:var(--text-muted);font-size:12px;margin-right:6px}.sources-detail[open]>summary::before{content:"▾"}.sources-detail .table-scroll{margin-top:10px}
      .source-badges{display:flex;gap:5px;flex-wrap:wrap}.source-badge{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;background:var(--plane);font-size:11.5px;text-decoration:none;color:var(--text-secondary)}
      .source-badge:hover{color:var(--text-primary)}.evidence-links{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:11.5px;color:var(--text-secondary)}
      .incident-facts{margin-top:8px;font-size:12px;font-weight:400;line-height:1.4}.incident-facts>summary{cursor:pointer;color:var(--text-secondary);list-style:none;width:max-content;max-width:100%}.incident-facts>summary::-webkit-details-marker{display:none}.incident-facts>summary::before{content:"▸";color:var(--text-muted);margin-right:5px}.incident-facts[open]>summary::before{content:"▾"}.incident-facts-list{display:grid;gap:7px;margin-top:7px}.incident-fact{padding:8px 9px;border:1px solid var(--border);border-radius:8px;background:var(--plane)}.incident-fact-source{font-weight:650;margin-bottom:4px}.incident-fact-row{display:flex;gap:6px;align-items:flex-start;margin-top:2px}.incident-fact-label{color:var(--text-muted);flex:0 0 auto}.incident-fact-value{min-width:0;overflow-wrap:anywhere}.incident-fact-links{display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}.incident-fact-links a{font-size:11.5px}
      .incident-data-types{margin-top:7px}.incident-data-types-title{color:var(--text-muted);margin-bottom:3px}.incident-data-group{margin-top:4px}.incident-data-group>summary{cursor:pointer;list-style:none;font-weight:600}.incident-data-group>summary::-webkit-details-marker{display:none}.incident-data-group>summary::before{content:"▸";color:var(--text-muted);margin-right:5px}.incident-data-group[open]>summary::before{content:"▾"}.incident-data-values{display:flex;gap:4px;flex-wrap:wrap;margin-top:5px}.incident-data-value{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;background:var(--surface);overflow-wrap:anywhere}
      .local-analysis{margin-top:9px;padding:9px 10px;border:1px solid var(--border);border-radius:8px;background:var(--plane);font-size:12.5px;font-weight:400;line-height:1.45}.local-analysis p{margin:6px 0 0}.local-score{display:inline-flex;align-items:center;padding:2px 7px;border:1px solid var(--border);border-radius:999px;font-weight:650}.local-analysis .evidence-links{margin-top:7px}
      .source-measures{white-space:normal!important}
      @media(max-width:700px){
        .topbar-inner{align-items:flex-start}.brand-sub{max-width:190px}.run-pill{white-space:normal;text-align:left}
        .incidents-card .table-scroll,.reliability .table-scroll{overflow:visible;max-height:none}
        #incidents-table thead,#sources-detail-table thead{display:none}
        #incidents-table,#incidents-table tbody,#incidents-table tr,#incidents-table td,#sources-detail-table,#sources-detail-table tbody,#sources-detail-table tr,#sources-detail-table td{display:block;width:100%}
        #incidents-table tr,#sources-detail-table tr{padding:11px 0;border-bottom:1px solid var(--grid)}
        #incidents-table td,#sources-detail-table td{border:0!important;padding:3px 0!important;white-space:normal!important;max-width:none!important;overflow:visible!important;width:auto!important}
        #incidents-table td[data-label]::before,#sources-detail-table td[data-label]::before{content:attr(data-label);display:inline-block;min-width:88px;margin-right:8px;color:var(--text-muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;vertical-align:top}
        #incidents-table .org-cell{font-size:16px;font-weight:650;padding-bottom:7px!important}#incidents-table .org-cell::before{display:none}
        #incidents-table .sources-cell::before{display:block;margin-bottom:4px}
        .incident-facts,.incident-fact{font-size:12.5px}.incident-fact-row{display:block}.incident-fact-label{display:block}
        .incident-data-group>summary{padding:2px 0}
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
  const localOnly = $("#f-local")?.getAttribute("aria-pressed") === "true";
  const selectedSource = $("#f-source")?.value || "";
  return state.incidents.filter((incident) => {
    const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
    const automotive = $("#f-auto")?.getAttribute("aria-pressed") === "true";
    const largeRetail = $("#f-grande-distrib")?.getAttribute("aria-pressed") === "true";
    const oceanLocations = new Set(["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"]);
    if (selectedSource && !(incident.sources || []).includes(selectedSource)) return false;
    if (ocean && !oceanLocations.has(incident.location)) return false;
    if (localOnly && !incident.local) return false;
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

  function factRow(label, value) {
    if (value === undefined || value === null || value === "") return "";
    return `<div class="incident-fact-row"><span class="incident-fact-label">${esc(label)} :</span><span class="incident-fact-value">${esc(value)}</span></div>`;
  }

  function renderDataTypes(values) {
    if (!Array.isArray(values) || !values.length) return "";
    const groups = new Map(DATA_TYPE_GROUP_ORDER.map((label) => [label, []]));
    const seen = new Set();
    values.forEach((value) => {
      const cleaned = String(value || "").trim();
      if (!cleaned || seen.has(cleaned)) return;
      seen.add(cleaned);
      groups.get(dataTypeGroup(cleaned)).push(cleaned);
    });
    const rendered = DATA_TYPE_GROUP_ORDER.map((label) => {
      const items = groups.get(label) || [];
      if (!items.length) return "";
      return `<details class="incident-data-group"><summary>${esc(label)} · ${items.length}</summary><div class="incident-data-values">${items.map((value) => `<span class="incident-data-value">${esc(value)}</span>`).join("")}</div></details>`;
    }).filter(Boolean).join("");
    return rendered ? `<div class="incident-data-types"><div class="incident-data-types-title">Données exposées :</div>${rendered}</div>` : "";
  }

  function claimStatusLabel(value) {
    return ({
      claimed: "Revendiqué",
      confirmed: "Confirmé",
      unconfirmed: "Non confirmé",
      denied: "Démenti",
    })[value] || value;
  }

  function affectedLabel(fact) {
    if (fact.affected_count_raw) return fact.affected_count_raw;
    if (fact.affected_count === undefined || fact.affected_count === null) return "";
    const units = {
      people: "personnes", accounts: "comptes", users: "utilisateurs",
      clients: "clients", records: "enregistrements", files: "fichiers",
    };
    const unit = units[fact.affected_unit] || fact.affected_unit || "";
    return `${formatNumber(fact.affected_count)}${unit ? ` ${unit}` : ""}`;
  }

  function factLinks(fact) {
    const links = [];
    const victim = safeUrl(fact.victim_website);
    if (victim) links.push(`<a href="${esc(victim)}" target="_blank" rel="noopener noreferrer">Site victime · ${esc(host(victim))}</a>`);
    const evidence = [...new Set((fact.evidence_urls || []).map(safeUrl).filter(Boolean))];
    evidence.slice(0, 4).forEach((url) => {
      if (url !== victim) links.push(`<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">Preuve · ${esc(host(url))}</a>`);
    });
    return links.length ? `<div class="incident-fact-links">${links.join("")}</div>` : "";
  }

  function renderSourceFact(fact) {
    if (!fact || !fact.source) return "";
    const rows = [
      factRow("Statut", fact.claim_status ? claimStatusLabel(fact.claim_status) : ""),
      factRow("Acteur", fact.threat_actor),
      factRow("Tiers impliqué", fact.third_party),
      factRow("Localisation précise", fact.fine_location),
      factRow("Données touchées", affectedLabel(fact)),
      factRow("Volume", fact.data_volume),
      factRow("Fichiers", fact.file_count !== undefined ? formatNumber(fact.file_count) : ""),
      renderDataTypes(fact.data_types),
      factRow("Vulnérabilités", Array.isArray(fact.vulnerabilities) ? fact.vulnerabilities.join(", ") : ""),
      factRow("CVSS", fact.cvss),
      factRow("Date d'attaque", fact.attack_date ? formatDate(fact.attack_date) : ""),
      factRow("Découverte", fact.discovered_date ? formatDate(fact.discovered_date) : ""),
      factRow("Score cyberattaque", fact.cyberattack_score !== undefined ? `${esc(fact.cyberattack_score)}/100` : ""),
      factRow("Impact", fact.impact),
      factRow("Synthèse", fact.summary),
      factRow("Évolution", fact.evolution),
    ].filter(Boolean);
    const links = factLinks(fact);
    if (!rows.length && !links) return "";
    return `<div class="incident-fact"><div class="incident-fact-source">${esc(sourceLabel(fact.source))}</div>${rows.join("")}${links}</div>`;
  }

  function renderSourceFacts(incident) {
    const facts = Array.isArray(incident.facts) ? incident.facts : [];
    const rendered = facts.map(renderSourceFact).filter(Boolean);
    if (!rendered.length) return "";
    return `<details class="incident-facts"><summary>Détails disponibles</summary><div class="incident-facts-list">${rendered.join("")}</div></details>`;
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

function renderLocalAnalysis(incident, enabled) {
  const local = incident.local;
  if (!enabled || !local) return "";
  const references = [...new Set((local.references || []).map(safeUrl).filter(Boolean))];
  const links = references.length
    ? `<div class="evidence-links"><span>Références :</span>${references.slice(0, 4).map((url, i) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="${esc(url)}">${esc(host(url))}${references.length > 1 ? ` ${i + 1}` : ""}</a>`).join("")}${references.length > 4 ? `<span>+${references.length - 4}</span>` : ""}</div>`
    : "";
  return `<div class="local-analysis"><span class="local-score">Score cyberattaque : ${esc(local.score)}/100</span><p><strong>Synthèse :</strong> ${esc(local.summary || "—")}</p>${links}</div>`;
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

    const localOnly = $("#f-local")?.getAttribute("aria-pressed") === "true";
    tableObserver?.disconnect();
    tbody.innerHTML = shown.map((incident) => `<tr>
      <td data-label="Date" class="num">${esc(incident.date || "—")}</td>
      <td data-label="Organisation" class="wrap-cell org-cell">${esc(incident.org || "Organisation inconnue")}${renderSourceFacts(incident)}${renderLocalAnalysis(incident, localOnly)}</td>
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

  function statusLevel(status) {
    const upper = String(status || "SKIPPED").toUpperCase();
    return upper === "OK" ? "ok" : (upper === "FAIL" ? "fail" : "attention");
  }

  function renderSources() {
    const rows = ((state.status && state.status.sources) || []).slice();
    const list = $("#sources-list");
    if (list) {
      list.innerHTML = rows.map((source) => {
        const level = statusLevel(source.status);
        const label = String(source.status || "SKIPPED").toUpperCase();
        return `<span class="source-state"><span class="source-led source-led--${level}" role="img" aria-label="${esc(label)}" title="${esc(label)}"></span>${esc(sourceLabel(source.id))}</span>`;
      }).join("");
    }
    renderSourceDetail(rows);
  }

  /** Détail homogène : mêmes six champs pour chaque source, sans cas
   * particulier — accessible sous la vue globale compacte via <details>. */
  function renderSourceDetail(rows) {
    const tbody = $("#sources-detail-table tbody");
    if (!tbody) return;
    tbody.innerHTML = rows.map((source) => {
      const label = String(source.status || "SKIPPED").toUpperCase();
      // Signal discret (§stabilisation pré-release) : un protocole peut
      // aboutir (OK) avec un historique réel plus court que la fenêtre
      // demandée — jamais un angle mort technique, juste une profondeur
      // connue à afficher. Générique pour toute source, vide sinon.
      const historyTitle = source.history_status === "TRUNCATED" && source.oldest_available_date
        ? `Historique disponible depuis le ${formatDate(source.oldest_available_date)}`
        : "";
      return `<tr>
        <td data-label="Source">${esc(sourceLabel(source.id))}</td>
        <td data-label="Statut"><span class="chip" data-status="${esc(label)}" title="${esc(historyTitle)}">${esc(label)}</span></td>
        <td data-label="Dernier item">${esc(formatDate(source.latest_item))}</td>
        <td data-label="Organisation">${esc(source.latest_item_org || "—")}</td>
        <td data-label="Items vus" class="num">${esc(source.items_seen ?? "—")}</td>
        <td data-label="Items dans la fenêtre" class="num">${esc(source.items_in_window ?? "—")}</td>
      </tr>`;
    }).join("");
  }

  function patchRunLabels() {
    const data = state.status;
    if (!data || !data.run || data.initialized === false) return;
    const run = data.run;
    const c = data.counts || { ok: 0, partial: 0, fail: 0, skipped: 0 };
    const totalSources = (data.sources || []).length || c.ok + c.partial + c.fail + c.skipped;
    const needsAttention = (data.blind_spots || []).length;
    if ($("#run-pill")) { $("#run-pill").dataset.status = run.overall; $("#run-pill").title = "Voir l’état détaillé des sources"; }
    if ($("#run-pill-text")) $("#run-pill-text").textContent = needsAttention ? `Sources : ${c.ok}/${totalSources} opérationnelles · ${needsAttention} à vérifier` : `Sources : ${c.ok}/${totalSources} opérationnelles`;
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