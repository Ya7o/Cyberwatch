/* Cyberwatch — runtime unique du dashboard, sans dépendance externe. */
(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));

  const OCEAN_LOCATIONS = new Set([
    "La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores",
  ]);
  const MONTHS = [
    "janv.", "févr.", "mars", "avr.", "mai", "juin",
    "juil.", "août", "sept.", "oct.", "nov.", "déc.",
  ];
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
  const SENSITIVE_MARKERS = [
    "sante", "medical", "patient", "diagnostic", "patholog", "ordonnance", "traitement", "vaccin",
    "nir", "securite sociale", "numero de securite sociale",
    "passeport", "carte d identite", "piece d identite", "permis de conduire", "biometr", "selfie",
    "mot de passe", "password", "hash", "token", "otp", "secret", "cle api", "authent",
    "iban", "rib", "bancair", "carte de paiement", "carte bancaire", "releve de compte",
    "revenu", "salaire", "patrimoine",
  ];
  const PERSONAL_EXACT = new Set([
    "nom", "prenom", "nom et prenom", "nom, prenom", "nom / prenom",
  ]);
  const PERSONAL_MARKERS = [
    "e-mail", "email", "telephone", "adresse postale", "date de naissance",
    "numero client", "identifiant client", "coordonnees personnelles",
  ];

  const state = {
    incidents: [],
    status: null,
    sort: { key: "date", dir: -1 },
    page: 1,
    pageSize: 50,
    filters: { ocean: false, local: false, source: "", org: "" },
  };

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[char]));
  }

  function normalize(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase("fr-FR")
      .trim();
  }

  function sourceLabel(id) {
    return ({
      BONJOURLAFUITE: "BonjourLaFuite",
      FRENCHBREACHES: "FrenchBreaches",
      CYBERATTAQUE_ORG: "Cyberattaque.org",
      RANSOMWARE_LIVE: "Ransomware.live",
      VEILLE_LLM: "veillellmReYt",
      CERT_MU_ALERTS: "CERT-MU",
    })[id] || String(id || "Source");
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(0, 10);
    return date.toLocaleDateString("fr-FR", {
      day: "2-digit", month: "short", year: "numeric",
    });
  }

  function formatNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString("fr-FR") : String(value || "");
  }

  function safeUrl(value) {
    if (!value) return "";
    try {
      const url = new URL(value, location.href);
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) {
      return "";
    }
  }

  function host(value) {
    try {
      return new URL(value).hostname.replace(/^www\./, "");
    } catch (_) {
      return "lien";
    }
  }

  function installCss() {
    const style = document.createElement("style");
    style.id = "dashboard-runtime-css";
    style.textContent = `
      .dashboard-charts{margin-top:var(--gap)}
      .filters-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:16px 0 4px}
      .org-search{min-width:min(320px,100%);flex:1 1 240px;font:inherit;font-size:13.5px;padding:7px 11px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-primary)}
      .btn-reset,.incident-details-toggle,.audit-pager button,.audit-pager select{font:inherit;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-secondary);cursor:pointer}
      .btn-reset{font-size:13.5px;padding:7px 12px}.incident-details-toggle{font-size:11.5px;padding:2px 7px;margin-left:8px;border-radius:999px}
      .sort-button{all:unset;cursor:pointer;color:inherit}
      .sort-button:focus-visible,.btn-quick:focus-visible,.btn-reset:focus-visible,.org-search:focus-visible,.theme-toggle:focus-visible,.incident-details-toggle:focus-visible,.audit-pager button:focus-visible,.audit-pager select:focus-visible{outline:2px solid var(--series-1);outline-offset:2px}
      .incidents-card .table-scroll{max-height:none}
      .audit-pager{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px;font-size:12.5px;color:var(--text-secondary)}
      .audit-pager-actions{display:flex;gap:8px;align-items:center}.audit-pager button,.audit-pager select{font-size:13px;padding:6px 9px}.audit-pager button:disabled{opacity:.45}
      .sources-list{display:flex;gap:9px 18px;flex-wrap:wrap;margin-top:12px}.source-state{display:inline-flex;align-items:center;gap:7px;font-size:14px}
      .source-led{width:9px;height:9px;border-radius:50%;background:var(--text-muted)}.source-led--ok{background:var(--status-ok)}.source-led--attention{background:var(--status-partial)}.source-led--fail{background:var(--status-fail)}
      .sources-detail{margin-top:14px}.sources-detail>summary{cursor:pointer;font-size:13px;color:var(--text-secondary)}.sources-detail .table-scroll{margin-top:10px}
      .source-badges,.evidence-links{display:flex;gap:6px;flex-wrap:wrap}.source-badge{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;background:var(--plane);font-size:11.5px;text-decoration:none;color:var(--text-secondary)}.source-badge:hover{color:var(--text-primary)}
      .evidence-links{margin-top:6px;font-size:11.5px;color:var(--text-secondary)}
      .data-sensitivity{display:inline-flex;margin-left:7px;padding:2px 7px;border-radius:999px;border:1px solid var(--border);font-size:11px;font-weight:650}.data-sensitivity--personal{background:rgba(217,154,0,.14)}.data-sensitivity--sensitive{background:rgba(214,69,69,.14)}.data-sensitivity--unknown{color:var(--text-secondary)}
      .incident-details-row[hidden]{display:none}.incident-details-cell{white-space:normal!important;background:var(--plane);padding:12px 14px!important}.incident-details-grid,.incident-facts-list{display:grid;gap:8px}
      .incident-summary,.local-analysis,.incident-fact{padding:9px 10px;border:1px solid var(--border);border-radius:8px;background:var(--surface);font-size:12.5px;line-height:1.45}.incident-fact-source{font-weight:650;margin-bottom:4px}
      .incident-fact-row{display:flex;gap:6px;margin-top:2px}.incident-fact-label{color:var(--text-muted);flex:none}.incident-fact-value{overflow-wrap:anywhere}
      .incident-data-types{margin-top:7px}.incident-data-types-title{color:var(--text-muted);margin-bottom:3px}.incident-data-group{margin-top:4px}.incident-data-group>summary{cursor:pointer;font-weight:600}.incident-data-values{display:flex;gap:4px;flex-wrap:wrap;margin-top:5px}.incident-data-value{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px}
      .local-score{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;font-weight:650}.local-analysis p{margin:6px 0 0}.bar-hit:focus{outline:none;stroke:var(--series-1);stroke-width:2}
      @media(max-width:700px){
        .topbar-inner{align-items:flex-start}.brand-sub{max-width:190px}.run-pill{white-space:normal;text-align:left}
        .incidents-card .table-scroll,.reliability .table-scroll{overflow:visible;max-height:none}
        #incidents-table thead,#sources-detail-table thead{display:none}
        #incidents-table,#incidents-table tbody,#incidents-table tr,#incidents-table td,#sources-detail-table,#sources-detail-table tbody,#sources-detail-table tr,#sources-detail-table td{display:block;width:100%}
        #incidents-table tr.incident-row,#sources-detail-table tr{padding:11px 0;border-bottom:1px solid var(--grid)}
        #incidents-table td:not(.incident-details-cell),#sources-detail-table td{border:0!important;padding:3px 0!important;white-space:normal!important;max-width:none!important}
        #incidents-table td[data-label]::before,#sources-detail-table td[data-label]::before{content:attr(data-label);display:inline-block;min-width:88px;margin-right:8px;color:var(--text-muted);font-size:10.5px;text-transform:uppercase}
        .org-cell{font-size:16px!important}.org-cell::before{display:none!important}.incident-details-row[hidden]{display:none!important}.incident-fact-row{display:block}.incident-fact-label{display:block}.audit-pager-actions{width:100%;justify-content:space-between}
      }
    `;
    document.head.appendChild(style);
  }

  function filteredIncidents() {
    const query = normalize(state.filters.org);
    return state.incidents.filter((incident) => {
      if (state.filters.source && !(incident.sources || []).includes(state.filters.source)) return false;
      if (state.filters.ocean && !OCEAN_LOCATIONS.has(incident.location)) return false;
      if (state.filters.local && !incident.local) return false;
      if (query && !normalize(incident.org).includes(query)) return false;
      return true;
    });
  }

  function countBy(rows, key, { dropUnknown = false } = {}) {
    const counts = new Map();
    rows.forEach((row) => {
      const value = row[key] || "Inconnu";
      if (dropUnknown && value === "Inconnu") return;
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    return Array.from(counts, ([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label, "fr"));
  }

  function monthRange(rows) {
    const keys = rows.map((row) => String(row.date || "").slice(0, 7)).filter(Boolean).sort();
    if (!keys.length) return [];
    let [year, month] = keys[0].split("-").map(Number);
    const [endYear, endMonth] = keys[keys.length - 1].split("-").map(Number);
    const result = [];
    while (year < endYear || (year === endYear && month <= endMonth)) {
      result.push(`${year}-${String(month).padStart(2, "0")}`);
      month += 1;
      if (month > 12) { month = 1; year += 1; }
    }
    return result;
  }

  const SVG_NS = "http://www.w3.org/2000/svg";

  function svgEl(name, attrs = {}, text) {
    const node = document.createElementNS(SVG_NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function bindTooltip(node, html, ariaLabel) {
    const tip = $("#tooltip");
    node.setAttribute("tabindex", "0");
    node.setAttribute("role", "img");
    node.setAttribute("aria-label", ariaLabel);
    const show = (event) => {
      if (!tip) return;
      tip.innerHTML = html;
      tip.hidden = false;
      const rect = tip.getBoundingClientRect();
      const target = node.getBoundingClientRect();
      const x = event?.clientX ?? target.left + target.width / 2;
      const y = event?.clientY ?? target.top + target.height / 2;
      tip.style.left = `${Math.max(8, Math.min(innerWidth - rect.width - 8, x + 14))}px`;
      tip.style.top = `${Math.max(8, Math.min(innerHeight - rect.height - 8, y + 14))}px`;
    };
    node.addEventListener("mouseenter", show);
    node.addEventListener("mousemove", show);
    node.addEventListener("focus", show);
    ["mouseleave", "blur"].forEach((eventName) => {
      node.addEventListener(eventName, () => { if (tip) tip.hidden = true; });
    });
  }

  function emptyChart(container) {
    if (container) container.innerHTML = '<p class="empty-chart">Aucun incident sur la sélection.</p>';
  }

  function barChartHorizontal(container, data) {
    if (!container) return;
    container.innerHTML = "";
    if (!data.length) return emptyChart(container);
    let rows = data;
    if (data.length > 9) {
      rows = data.slice(0, 8).concat([{ label: "Autres", value: data.slice(8).reduce((sum, row) => sum + row.value, 0) }]);
    }
    const width = Math.max(container.clientWidth || 520, 320);
    const rowHeight = 26;
    const height = rows.length * rowHeight + 16;
    const labelWidth = Math.min(190, Math.max(110, width * 0.36));
    const plotWidth = width - labelWidth - 44;
    const max = Math.max(...rows.map((row) => row.value), 1);
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": "Répartition par catégorie" });
    rows.forEach((row, index) => {
      const y = index * rowHeight + 8;
      const barWidth = Math.max(3, (row.value / max) * plotWidth);
      svg.appendChild(svgEl("text", { class: "tick-label", x: labelWidth - 10, y: y + rowHeight / 2, "text-anchor": "end", "dominant-baseline": "middle" }, row.label.length > 26 ? `${row.label.slice(0, 25)}…` : row.label));
      svg.appendChild(svgEl("rect", { class: "bar", x: labelWidth, y: y + 5, width: barWidth, height: rowHeight - 12, rx: 4 }));
      svg.appendChild(svgEl("text", { class: "value-label", x: labelWidth + barWidth + 8, y: y + rowHeight / 2, "dominant-baseline": "middle" }, String(row.value)));
      const hit = svgEl("rect", { class: "bar-hit", x: 0, y, width, height: rowHeight });
      bindTooltip(hit, `<strong>${esc(row.label)}</strong> ${row.value} incident${row.value > 1 ? "s" : ""}`, `${row.label} : ${row.value} incidents`);
      svg.appendChild(hit);
    });
    container.appendChild(svg);
  }

  function barChartTime(container, data) {
    if (!container) return;
    container.innerHTML = "";
    if (!data.length) return emptyChart(container);
    const width = Math.max(container.clientWidth || 520, 320);
    const height = 240;
    const margin = { top: 14, right: 8, bottom: 34, left: 34 };
    const plotWidth = width - margin.left - margin.right;
    const plotHeight = height - margin.top - margin.bottom;
    const max = Math.max(...data.map((row) => row.value), 1);
    const step = plotWidth / data.length;
    const barWidth = Math.max(3, Math.min(38, step - 6));
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": "Incidents par mois" });
    data.forEach((point, index) => {
      const barHeight = (point.value / max) * plotHeight;
      const x = margin.left + index * step + (step - barWidth) / 2;
      const y = margin.top + plotHeight - barHeight;
      if (point.value) svg.appendChild(svgEl("rect", { class: "bar", x, y, width: barWidth, height: barHeight, rx: 4 }));
      const [year, month] = point.label.split("-");
      const label = `${MONTHS[Number(month) - 1]} ${year.slice(2)}`;
      const hit = svgEl("rect", { class: "bar-hit", x: margin.left + index * step, y: margin.top, width: step, height: plotHeight });
      bindTooltip(hit, `<strong>${esc(label)}</strong> ${point.value} incident${point.value > 1 ? "s" : ""}`, `${label} : ${point.value} incidents`);
      svg.appendChild(hit);
      const every = Math.ceil(data.length / 8);
      if (index % every === 0 || index === data.length - 1) {
        svg.appendChild(svgEl("text", { class: "tick-label", x: margin.left + index * step + step / 2, y: height - 12, "text-anchor": "middle" }, label));
      }
    });
    container.appendChild(svg);
  }

  function sensitivity(incident) {
    const facts = Array.isArray(incident.facts) ? incident.facts : [];
    const values = facts.flatMap((fact) => Array.isArray(fact.data_types) ? fact.data_types : []).map(normalize);
    if (values.some((value) => SENSITIVE_MARKERS.some((marker) => value.includes(marker)))) {
      return ["sensitive", "Données sensibles"];
    }
    if (values.some((value) => PERSONAL_EXACT.has(value) || PERSONAL_MARKERS.some((marker) => value.includes(marker)))) {
      return ["personal", "Données personnelles"];
    }
    if (values.length || facts.some((fact) => fact.affected_count != null || fact.data_volume || fact.file_count != null)) {
      return ["unknown", "Données non qualifiées"];
    }
    return null;
  }

  function sensitivityHtml(incident) {
    const result = sensitivity(incident);
    return result ? `<span class="data-sensitivity data-sensitivity--${result[0]}">${result[1]}</span>` : "";
  }

  function dataTypeGroup(value) {
    const normalized = normalize(value);
    for (const [label, keywords] of DATA_TYPE_GROUP_RULES) {
      if (keywords.some((keyword) => normalized.includes(keyword))) return label;
    }
    return "Autres";
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

  function factRow(label, value) {
    if (value === undefined || value === null || value === "") return "";
    return `<div class="incident-fact-row"><span class="incident-fact-label">${esc(label)} :</span><span class="incident-fact-value">${esc(value)}</span></div>`;
  }

  function attackFlowLabel(values) {
    if (!Array.isArray(values)) return "";
    return values.map((step) => step?.action).filter(Boolean).slice(0, 5).join(" → ");
  }

  function affectedLabel(fact) {
    if (fact.affected_count_raw) return fact.affected_count_raw;
    if (fact.affected_count == null) return "";
    const units = { people: "personnes", accounts: "comptes", users: "utilisateurs", clients: "clients", records: "enregistrements", files: "fichiers" };
    const unit = units[fact.affected_unit] || fact.affected_unit || "";
    return `${formatNumber(fact.affected_count)}${unit ? ` ${unit}` : ""}`;
  }

  function duplicatesDedicatedFileCount(fact) {
    if (String(fact.affected_unit || "").trim().toLowerCase() !== "files") return false;
    if (fact.affected_count == null || fact.file_count == null) return false;
    const affected = Number(fact.affected_count);
    const files = Number(fact.file_count);
    return Number.isFinite(affected) && Number.isFinite(files) && affected === files;
  }

  function factHtml(fact) {
    const access = ({
      phishing: "Phishing",
      compromised_credentials: "Identifiants compromis",
      vulnerability_exploitation: "Exploitation d’une vulnérabilité",
      remote_access: "Accès distant",
      third_party: "Tiers compromis",
      malware: "Malware",
      other: "Autre",
    })[fact.initial_access] || fact.initial_access || "";
    const claimStatus = ({
      claimed: "Revendiqué", confirmed: "Confirmé", unconfirmed: "Non confirmé", denied: "Démenti",
    })[fact.claim_status] || fact.claim_status || "";
    const rows = [
      factRow("Statut", claimStatus),
      factRow("Acteur", fact.threat_actor),
      factRow("Tiers impliqué", fact.third_party),
      factRow("Vecteur d'entrée", access),
      factRow("Déroulé", attackFlowLabel(fact.attack_flow)),
      factRow("Localisation précise", fact.fine_location),
      factRow("Données touchées", duplicatesDedicatedFileCount(fact) ? "" : affectedLabel(fact)),
      factRow("Volume", fact.data_volume),
      factRow("Fichiers", fact.file_count != null ? formatNumber(fact.file_count) : ""),
      renderDataTypes(fact.data_types),
      factRow("Vulnérabilités", Array.isArray(fact.vulnerabilities) ? fact.vulnerabilities.join(", ") : ""),
      factRow("CVSS", fact.cvss),
      factRow("Date d'attaque", fact.attack_date ? formatDate(fact.attack_date) : ""),
      factRow("Découverte", fact.discovered_date ? formatDate(fact.discovered_date) : ""),
      factRow("Score cyberattaque", fact.cyberattack_score != null ? `${fact.cyberattack_score}/100` : ""),
      factRow("Impact", fact.impact),
      factRow("Synthèse", fact.summary),
      factRow("Évolution", fact.evolution),
    ].filter(Boolean);
    const links = [safeUrl(fact.victim_website), ...(fact.evidence_urls || []).map(safeUrl)]
      .filter(Boolean).slice(0, 4);
    if (links.length) {
      rows.push(`<div class="evidence-links">${links.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>`);
    }
    return rows.length
      ? `<div class="incident-fact"><div class="incident-fact-source">${esc(sourceLabel(fact.source))}</div>${rows.join("")}</div>`
      : "";
  }

  function detailHtml(incident) {
    const parts = [];
    if (incident.summary) {
      parts.push(`<div class="incident-summary"><strong>Synthèse :</strong> ${esc(incident.summary)}</div>`);
    }
    const facts = (incident.facts || []).map(factHtml).filter(Boolean);
    if (facts.length) parts.push(`<div class="incident-facts-list">${facts.join("")}</div>`);
    if (incident.local) {
      const references = (incident.local.references || []).map(safeUrl).filter(Boolean).slice(0, 4);
      parts.push(`<div class="local-analysis"><span class="local-score">Score cyberattaque : ${esc(incident.local.score)}/100</span><p><strong>Analyse locale :</strong> ${esc(incident.local.summary || "—")}</p>${references.length ? `<div class="evidence-links">${references.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>` : ""}</div>`);
    }
    return parts.length
      ? `<div class="incident-details-grid">${parts.join("")}</div>`
      : '<span class="muted">Aucun enrichissement supplémentaire disponible.</span>';
  }

  function sourceHomes() {
    const homes = new Map();
    (state.status?.sources || []).forEach((source) => {
      const url = safeUrl(source.url);
      if (url) homes.set(source.id, url);
    });
    return homes;
  }

  function sourceLinks(incident) {
    const homes = sourceHomes();
    const badges = (incident.sources || []).map((id) => {
      const label = sourceLabel(id);
      const url = homes.get(id);
      return url
        ? `<a class="source-badge" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`
        : `<span class="source-badge">${esc(label)}</span>`;
    }).join("");
    const urls = Array.from(new Set((incident.urls || []).map(safeUrl).filter(Boolean))).slice(0, 3);
    return `<div class="source-badges">${badges}</div>${urls.length ? `<div class="evidence-links">${urls.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>` : ""}`;
  }

  function renderTable(rows) {
    const sorted = rows.slice().sort((a, b) => {
      const key = state.sort.key;
      const left = key === "items" ? (a.sources || []).length : (a[key] || "");
      const right = key === "items" ? (b.sources || []).length : (b[key] || "");
      return left < right ? -state.sort.dir : left > right ? state.sort.dir : 0;
    });
    const pages = Math.max(1, Math.ceil(sorted.length / state.pageSize));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * state.pageSize;
    const shown = sorted.slice(start, start + state.pageSize);
    const tbody = $("#incidents-table tbody");
    tbody.innerHTML = shown.length ? shown.map((incident, index) => {
      const id = `incident-details-${String(incident.id || `${start + index}`).replace(/[^a-zA-Z0-9_-]/g, "-")}`;
      return `<tr class="incident-row">
        <td data-label="Date" class="num">${esc(incident.date || "—")}</td>
        <td data-label="Organisation" class="wrap-cell org-cell"><strong>${esc(incident.org || "Organisation inconnue")}</strong>${sensitivityHtml(incident)}<button class="incident-details-toggle" type="button" aria-expanded="false" aria-controls="${id}">Détails</button></td>
        <td data-label="Territoire">${esc(incident.location || "—")}</td>
        <td data-label="Secteur">${esc(incident.sector || "—")}</td>
        <td data-label="Menace">${esc(incident.threat || "—")}</td>
        <td data-label="Sources">${sourceLinks(incident)}</td>
      </tr>
      <tr class="incident-details-row" id="${id}" hidden><td class="incident-details-cell" colspan="6">${detailHtml(incident)}</td></tr>`;
    }).join("") : '<tr><td colspan="6" class="muted">Aucun incident ne correspond aux filtres.</td></tr>';

    $("#table-count").textContent = sorted.length
      ? `${start + 1}–${Math.min(start + shown.length, sorted.length)} sur ${sorted.length} incidents`
      : "0 incident";
    $("#audit-pager").innerHTML = `<span>Page ${state.page} / ${pages}</span><div class="audit-pager-actions">
      <label>Lignes <select id="audit-page-size"><option>25</option><option>50</option><option>100</option></select></label>
      <button id="audit-prev" type="button" ${state.page <= 1 ? "disabled" : ""}>Précédent</button>
      <button id="audit-next" type="button" ${state.page >= pages ? "disabled" : ""}>Suivant</button>
    </div>`;
    $("#audit-page-size").value = String(state.pageSize);
  }

  function renderKpis(rows) {
    const now = new Date();
    const cutoff = new Date(now.getTime() - 30 * 864e5);
    $("#kpi-incidents").textContent = rows.length;
    $("#kpi-30d").textContent = rows.filter((incident) => {
      const date = new Date(incident.date);
      return !Number.isNaN(date.getTime()) && date >= cutoff && date <= now;
    }).length;
    $("#kpi-ocean").textContent = rows.filter((incident) => OCEAN_LOCATIONS.has(incident.location)).length;
    $("#kpi-ransomware").textContent = rows.filter((incident) => normalize(incident.threat).includes("ransomware")).length;
    $("#kpi-incidents-note").textContent = rows.length === state.incidents.length
      ? "événements uniques dans la base"
      : "événements correspondant aux filtres actifs";
  }

  function renderCharts(rows) {
    const months = monthRange(rows);
    const perMonth = new Map();
    rows.forEach((incident) => {
      const key = String(incident.date || "").slice(0, 7);
      if (key) perMonth.set(key, (perMonth.get(key) || 0) + 1);
    });
    barChartTime($("#chart-month"), months.map((key) => ({ label: key, value: perMonth.get(key) || 0 })));
    barChartHorizontal($("#chart-location"), countBy(rows, "location"));
    barChartHorizontal($("#chart-sector"), countBy(rows, "sector", { dropUnknown: true }));
    barChartHorizontal($("#chart-threat"), countBy(rows, "threat"));
    const known = rows.filter((incident) => (incident.sector || "Inconnu") !== "Inconnu").length;
    $("#sector-note").textContent = rows.length
      ? `${known} incidents sur ${rows.length} ont un secteur documenté (${Math.round(100 * known / rows.length)} %).`
      : "";
  }

  function renderSources() {
    const rows = state.status?.sources || [];
    const list = $("#sources-list");
    list.innerHTML = rows.map((source) => {
      const status = String(source.status || "SKIPPED").toUpperCase();
      const level = status === "OK" ? "ok" : status === "FAIL" ? "fail" : "attention";
      return `<span class="source-state"><span class="source-led source-led--${level}" role="img" aria-label="${esc(status)}"></span>${esc(sourceLabel(source.id))}</span>`;
    }).join("");
    renderSourceDetail(rows);
  }

  function renderSourceDetail(rows) {
    $("#sources-detail-table tbody").innerHTML = rows.map((source) => {
      const status = String(source.status || "SKIPPED").toUpperCase();
      return `<tr>
        <td data-label="Source">${esc(sourceLabel(source.id))}</td>
        <td data-label="Statut"><span class="chip" data-status="${esc(status)}">${esc(status)}</span></td>
        <td data-label="Dernier item">${esc(formatDate(source.latest_item))}</td>
        <td data-label="Organisation">${esc(source.latest_item_org || "—")}</td>
        <td data-label="Items vus" class="num">${esc(source.items_seen ?? "—")}</td>
        <td data-label="Items dans la fenêtre" class="num">${esc(source.items_in_window ?? "—")}</td>
      </tr>`;
    }).join("");
  }

  function renderBlindSpots() {
    const box = $("#blindspots");
    const list = $("#blindspots-list");
    if (!box || !list) return;
    const spots = state.status?.blind_spots || [];
    if (!spots.length) {
      box.hidden = true;
      list.innerHTML = "";
      return;
    }
    box.hidden = false;
    list.innerHTML = spots.map((spot) => `
      <li><strong>${esc(spot.id)}</strong> — ${esc(spot.status || "À vérifier")}${spot.coverage != null ? ` ${esc(spot.coverage)}%` : ""}${spot.detail ? ` (${esc(spot.detail)})` : ""}${spot.reason ? ` : ${esc(spot.reason)}` : ""}</li>
    `).join("");
  }

  function renderRun() {
    const data = state.status;
    const pill = $("#run-pill");
    const text = $("#run-pill-text");
    if (data?.initialized === false) {
      pill.dataset.status = "";
      text.textContent = "Base non initialisée";
      return;
    }
    if (!data?.run?.id) {
      pill.dataset.status = "";
      text.textContent = "Aucune collecte";
      return;
    }
    const counts = data.counts || { ok: 0, partial: 0, fail: 0, skipped: 0 };
    const total = (data.sources || []).length || counts.ok + counts.partial + counts.fail + counts.skipped;
    const needsAttention = (data.blind_spots || []).length;
    pill.dataset.status = data.run.overall;
    text.textContent = needsAttention
      ? `Sources : ${counts.ok}/${total} opérationnelles · ${needsAttention} à vérifier`
      : `Sources : ${counts.ok}/${total} opérationnelles`;
  }

  function render() {
    renderRun();
    renderBlindSpots();
    renderSources();
    if (state.status?.initialized === false) {
      $("#table-count").textContent = "Base non initialisée";
      $("#incidents-table tbody").innerHTML = '<tr><td colspan="6">Aucune collecte validée disponible.</td></tr>';
      return;
    }
    const rows = filteredIncidents();
    renderKpis(rows);
    renderCharts(rows);
    renderTable(rows);
  }

  function setupControls() {
    $("#f-ocean-indien").addEventListener("click", () => {
      state.filters.ocean = !state.filters.ocean;
      $("#f-ocean-indien").setAttribute("aria-pressed", String(state.filters.ocean));
      state.page = 1;
      render();
    });
    $("#f-local").addEventListener("click", () => {
      state.filters.local = !state.filters.local;
      $("#f-local").setAttribute("aria-pressed", String(state.filters.local));
      state.page = 1;
      render();
    });
    $("#f-source").addEventListener("change", (event) => {
      state.filters.source = event.target.value || "";
      state.page = 1;
      render();
    });
    let searchTimer;
    $("#f-org").addEventListener("input", (event) => {
      clearTimeout(searchTimer);
      const value = event.target.value;
      searchTimer = setTimeout(() => {
        state.filters.org = value;
        state.page = 1;
        render();
      }, 180);
    });
    $("#f-reset").addEventListener("click", () => {
      state.filters = { ocean: false, local: false, source: "", org: "" };
      $("#f-ocean-indien").setAttribute("aria-pressed", "false");
      $("#f-local").setAttribute("aria-pressed", "false");
      $("#f-source").value = "";
      $("#f-org").value = "";
      state.page = 1;
      render();
    });

    $$("#incidents-table th[data-sort] .sort-button").forEach((button) => {
      button.addEventListener("click", () => {
        const th = button.closest("th");
        const key = th.dataset.sort;
        state.sort = {
          key,
          dir: state.sort.key === key ? -state.sort.dir : (key === "date" ? -1 : 1),
        };
        $$("#incidents-table th[data-sort]").forEach((other) => {
          other.setAttribute("aria-sort", other === th
            ? (state.sort.dir === 1 ? "ascending" : "descending")
            : "none");
        });
        state.page = 1;
        render();
      });
    });

    $("#incidents-table tbody").addEventListener("click", (event) => {
      const button = event.target.closest(".incident-details-toggle");
      if (!button) return;
      const row = document.getElementById(button.getAttribute("aria-controls"));
      const open = button.getAttribute("aria-expanded") === "true";
      button.setAttribute("aria-expanded", String(!open));
      button.textContent = open ? "Détails" : "Masquer";
      row.hidden = open;
    });

    $("#audit-pager").addEventListener("click", (event) => {
      if (event.target.id === "audit-prev" && state.page > 1) {
        state.page -= 1;
        render();
      } else if (event.target.id === "audit-next") {
        state.page += 1;
        render();
      }
    });
    $("#audit-pager").addEventListener("change", (event) => {
      if (event.target.id !== "audit-page-size") return;
      state.pageSize = Number(event.target.value) || 50;
      state.page = 1;
      render();
    });
  }

  function setupTheme() {
    const stored = localStorage.getItem("cyberwatch-theme");
    if (stored) document.documentElement.dataset.theme = stored;
    $("#theme-toggle").addEventListener("click", () => {
      const dark = document.documentElement.dataset.theme === "dark"
        || (!document.documentElement.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
      const next = dark ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("cyberwatch-theme", next);
      renderCharts(filteredIncidents());
    });
  }

  function setupResize() {
    let timer;
    addEventListener("resize", () => {
      clearTimeout(timer);
      timer = setTimeout(() => renderCharts(filteredIncidents()), 200);
    });
  }

  async function load(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-cache" });
      if (!response.ok) throw new Error(String(response.status));
      return await response.json();
    } catch (error) {
      console.warn(`Données indisponibles : ${path}`, error);
      return fallback;
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    installCss();
    const [incidents, status] = await Promise.all([
      load("assets/data/incidents.json", []),
      load("assets/data/status.json", null),
    ]);
    state.incidents = Array.isArray(incidents) ? incidents : [];
    state.status = status;
    setupTheme();
    setupControls();
    setupResize();
    render();
  });
})();
