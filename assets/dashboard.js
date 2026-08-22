/* Cyberwatch — runtime unique du dashboard, sans dépendance externe.
   Un état, trois vues (Veille / Recherche / Analyse), un seul chargement par
   fichier de données. Remplace app.js + p2.js + p3.js, qui recalculaient
   chacun les mêmes agrégats sur un périmètre implicite différent — d'où les
   chiffres contradictoires que l'audit a mesurés (154 vs 160 incidents sur
   « 30 jours », par exemple). Les signaux et indicateurs de l'Analyse sont
   calculés en Python (cyberwatch/analytics.py) et publiés dans status.json :
   ce fichier ne fait que les afficher. */
(() => {
  "use strict";

  const { esc, normalize, safeUrl, host, formatDate, formatDateTime, formatNumber,
    plural, setSourceLabels, sourceLabel, load, reportDataFailure,
    countBy, buildSearchIndex } = window.CW;

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const DAY = 864e5;
  const VIEWS = ["veille", "recherche", "analyse"];

  const state = {
    view: "veille",
    filters: { q: "", threat: "", sector: "", location: "", source: "", period: "all" },
    sort: "date-desc",
    page: 1,
    pageSize: 30,

    byId: new Map(),
    latestRows: [],
    incidentsRows: [],
    incidentsLoaded: false,
    incidentsLoading: false,
    incidentsFailed: false,
    searchIndex: null,

    status: null,
    analytics: null,
    facts: null,
    factsPromise: null,

    dataOk: true,
    statusOk: true,
  };

  // -------------------------------------------------------------- graphiques

  const SVG_NS = "http://www.w3.org/2000/svg";
  const MONTHS_SHORT = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];

  function svgEl(name, attrs = {}, text) {
    const node = document.createElementNS(SVG_NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function bindTooltip(node, html) {
    const tip = $("#tooltip");
    node.setAttribute("aria-hidden", "true");
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
    ["mouseleave"].forEach((eventName) => node.addEventListener(eventName, () => { if (tip) tip.hidden = true; }));
  }

  function emptyChart(container, message = "Aucun incident sur la sélection.") {
    if (container) container.innerHTML = `<p class="empty-chart">${esc(message)}</p>`;
  }

  function wrapChartLabel(value, maxChars, maxLines) {
    const words = String(value || "").trim().split(/\s+/).filter(Boolean);
    if (!words.length) return [""];
    const lines = [];
    let current = "";
    let index = 0;
    while (index < words.length && lines.length < maxLines) {
      const candidate = current ? `${current} ${words[index]}` : words[index];
      if (candidate.length <= maxChars || !current) { current = candidate; index += 1; }
      else { lines.push(current); current = ""; }
    }
    if (current && lines.length < maxLines) lines.push(current);
    if (index < words.length && lines.length) {
      const last = lines.length - 1;
      lines[last] = `${lines[last].slice(0, Math.max(1, maxChars - 1)).trimEnd()}…`;
    }
    return lines;
  }

  function chartLabel(intro, rows) {
    if (!rows.length) return intro;
    const listed = rows.slice(0, 8).map((row) => `${row.label} ${row.value}`).join(", ");
    return `${intro} : ${listed}${rows.length > 8 ? `, et ${rows.length - 8} autres` : ""}.`;
  }

  function barChartHorizontal(container, data, { onSelect } = {}) {
    if (!container) return;
    container.innerHTML = "";
    if (!data.length) return emptyChart(container);
    let rows = data;
    if (data.length > 9) {
      rows = data.slice(0, 8).concat([{ label: "Autres", value: data.slice(8).reduce((sum, row) => sum + row.value, 0) }]);
    }
    const width = Math.max(container.clientWidth || 520, 280);
    const isMobile = width <= 700;
    const rowHeight = isMobile ? 44 : 32;
    const height = rows.length * rowHeight + 12;
    const labelWidth = isMobile ? Math.min(180, Math.max(140, width * 0.48)) : Math.min(190, Math.max(110, width * 0.36));
    const right = isMobile ? 36 : 44;
    const plotWidth = Math.max(64, width - labelWidth - right);
    const max = Math.max(...rows.map((row) => row.value), 1);
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": chartLabel("Répartition par catégorie", rows) });
    rows.forEach((row, index) => {
      const y = index * rowHeight + 6;
      const barWidth = Math.max(3, (row.value / max) * plotWidth);
      const maxChars = Math.max(10, Math.floor((labelWidth - 10) / (isMobile ? 6.7 : 7.1)));
      const label = svgEl("text", { class: "category-label", x: 0, y: isMobile ? y + 13 : y + 16 });
      wrapChartLabel(row.label, maxChars, isMobile ? 2 : 1).forEach((line, lineIndex) => {
        label.appendChild(svgEl("tspan", { x: 0, dy: lineIndex === 0 ? 0 : 14 }, line));
      });
      label.appendChild(svgEl("title", {}, row.label));
      svg.appendChild(label);
      const barY = isMobile ? y + 10 : y + 5;
      svg.appendChild(svgEl("rect", { class: "bar", x: labelWidth, y: barY, width: barWidth, height: 18, rx: 4 }));
      svg.appendChild(svgEl("text", { class: "value-label", x: Math.min(width - 4, labelWidth + barWidth + 8), y: barY + 13 }, String(row.value)));
      const hit = svgEl("rect", { class: "bar-hit", x: 0, y, width, height: rowHeight });
      bindTooltip(hit, `<strong>${esc(row.label)}</strong> ${row.value} incident${plural(row.value, "", "s")}`);
      if (onSelect && row.label !== "Autres") {
        hit.style.cursor = "pointer";
        hit.addEventListener("click", () => onSelect(row.label));
      }
      svg.appendChild(hit);
    });
    container.appendChild(svg);
  }

  function barChartTime(container, data) {
    if (!container) return;
    container.innerHTML = "";
    if (!data.length) return emptyChart(container);
    const visibleWidth = Math.max(container.clientWidth || 520, 320);
    const width = Math.max(visibleWidth, data.length * 50 + 52);
    const height = 260;
    const margin = { top: 28, right: 8, bottom: 38, left: 34 };
    const plotWidth = width - margin.left - margin.right;
    const plotHeight = height - margin.top - margin.bottom;
    const max = Math.max(...data.map((row) => row.value), 1);
    const step = plotWidth / data.length;
    const barWidth = Math.max(5, Math.min(36, step - 8));
    const svg = svgEl("svg", {
      viewBox: `0 0 ${width} ${height}`, width, height, role: "img",
      "aria-label": chartLabel("Incidents par mois", data.filter((point) => point.value)),
    });
    data.forEach((point, index) => {
      const barHeight = (point.value / max) * plotHeight;
      const x = margin.left + index * step + (step - barWidth) / 2;
      const y = margin.top + plotHeight - barHeight;
      if (point.value) svg.appendChild(svgEl("rect", { class: "bar", x, y, width: barWidth, height: barHeight, rx: 4 }));
      svg.appendChild(svgEl("text", { class: "month-value-label", x: margin.left + index * step + step / 2, y: Math.max(14, y - 7), "text-anchor": "middle" }, String(point.value)));
      const label = point.label;
      const hit = svgEl("rect", { class: "bar-hit", x: margin.left + index * step, y: margin.top, width: step, height: plotHeight });
      bindTooltip(hit, `<strong>${esc(label)}</strong> ${point.value} incident${plural(point.value, "", "s")}`);
      svg.appendChild(hit);
      const every = Math.ceil(data.length / 10);
      if (index % every === 0 || index === data.length - 1) {
        svg.appendChild(svgEl("text", { class: "tick-label", x: margin.left + index * step + step / 2, y: height - 12, "text-anchor": "middle" }, label));
      }
    });
    container.appendChild(svg);
  }

  function monthLabel(key) {
    const [year, month] = key.split("-");
    return `${MONTHS_SHORT[Number(month) - 1]} ${year.slice(2)}`;
  }

  /* Une ligne = une dimension. Pas d'axe : les valeurs de départ/arrivée
     suffisent, et le tracé porte le reste dans son `aria-label`. */
  function sparklineRow(months, values, label) {
    const row = document.createElement("div");
    row.className = "sparkline-row";
    const width = 220;
    const height = 28;
    const max = Math.max(...values, 1);
    const step = values.length > 1 ? width / (values.length - 1) : 0;
    const points = values.map((value, index) => {
      const x = index * step;
      const y = height - (value / max) * (height - 4) - 2;
      return [x, y];
    });
    const described = months.map((month, index) => `${monthLabel(month)} ${values[index]}`).join(", ");
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `${label} : ${described}` });
    svg.appendChild(svgEl("polyline", { points: points.map((p) => p.join(",")).join(" ") }));
    points.forEach(([x, y]) => svg.appendChild(svgEl("circle", { cx: x, cy: y, r: 1.6 })));
    row.innerHTML = `<span class="label">${esc(label)}</span>`;
    row.appendChild(svg);
    const endpoint = document.createElement("span");
    endpoint.className = "endpoint";
    endpoint.textContent = `${values[0]} → ${values[values.length - 1]}`;
    row.appendChild(endpoint);
    return row;
  }

  // ------------------------------------------------------------- fiche incident

  const DATA_TYPE_GROUP_ORDER = ["Identité & coordonnées", "Profession / formation", "Finance & transactions", "Santé", "Accès & authentification", "Autres"];
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
  const PERSONAL_EXACT = new Set(["nom", "prenom", "nom et prenom", "nom, prenom", "nom / prenom"]);
  const PERSONAL_MARKERS = ["e-mail", "email", "telephone", "adresse postale", "date de naissance", "numero client", "identifiant client", "coordonnees personnelles"];

  function sensitivity(incident) {
    const facts = Array.isArray(incident.facts) ? incident.facts : [];
    const values = facts.flatMap((fact) => Array.isArray(fact.data_types) ? fact.data_types : []).map(normalize);
    if (values.some((value) => SENSITIVE_MARKERS.some((marker) => value.includes(marker)))) return ["sensitive", "Données sensibles"];
    if (values.some((value) => PERSONAL_EXACT.has(value) || PERSONAL_MARKERS.some((marker) => value.includes(marker)))) return ["personal", "Données personnelles"];
    if (values.length || facts.some((fact) => fact.affected_count != null || fact.data_volume || fact.file_count != null || fact.rich_facts)) return ["unknown", "Données non qualifiées"];
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

  function richStatusLabel(value) {
    return ({ confirmed: "Confirmé", reported: "Rapporté", claimed: "Revendiqué", unknown: "Statut non établi" })[value] || value || "Statut non établi";
  }
  function richUnitLabel(value) {
    return ({ people: "personnes", accounts: "comptes", users: "utilisateurs", clients: "clients", records: "enregistrements", files: "fichiers" })[value] || value || "";
  }
  function richEvidenceLine(record) {
    const pieces = [];
    if (record.scope) pieces.push(record.scope);
    if (record.date) pieces.push(formatDate(record.date));
    pieces.push(richStatusLabel(record.status));
    return pieces.filter(Boolean).join(" · ");
  }

  function renderRichFacts(rich) {
    if (!rich || typeof rich !== "object") return "";
    const sections = [];
    const counts = Array.isArray(rich.affected_counts) ? rich.affected_counts : [];
    if (counts.length) {
      const rows = counts.map((record) => {
        const value = `${formatNumber(record.value)} ${richUnitLabel(record.unit)}`.trim();
        const meta = richEvidenceLine(record);
        const evidence = record.evidence ? `<div class="muted">${esc(record.evidence)}</div>` : "";
        return `<div class="incident-fact-row"><span class="incident-fact-label">${esc(value)}</span><span class="incident-fact-value">${esc(meta)}</span></div>${evidence}`;
      }).join("");
      sections.push(`<div class="incident-data-types"><div class="incident-data-types-title">Faits chiffrés documentés :</div>${rows}</div>`);
    }
    const renderEntities = (label, values) => {
      if (!Array.isArray(values) || !values.length) return "";
      return `<div class="incident-data-types"><div class="incident-data-types-title">${esc(label)} :</div>${values.map((record) => `<div class="incident-fact-row"><span class="incident-fact-label">${esc(record.value || "Périmètre")}</span><span class="incident-fact-value">${esc(richEvidenceLine(record))}</span></div>${record.evidence ? `<div class="muted">${esc(record.evidence)}</div>` : ""}`).join("")}</div>`;
    };
    const systems = renderEntities("Systèmes concernés", rich.affected_systems);
    if (systems) sections.push(systems);
    const datasets = renderEntities("Périmètres de données", rich.affected_datasets);
    if (datasets) sections.push(datasets);
    const claims = Array.isArray(rich.claims) ? rich.claims.filter((claim) => claim.kind === "statement") : [];
    if (claims.length) {
      sections.push(`<details class="incident-data-group"><summary>Chronologie / déclarations · ${claims.length}</summary><div class="incident-data-values">${claims.map((claim) => `<div><strong>${esc(richEvidenceLine(claim))}</strong>${claim.evidence ? `<div class="muted">${esc(claim.evidence)}</div>` : ""}</div>`).join("")}</div></details>`);
    }
    return sections.join("");
  }

  function narrativeContains(container, detail) {
    const haystack = normalize(container).replace(/\s+/g, " ");
    const needle = normalize(detail).replace(/\s+/g, " ");
    return Boolean(haystack && needle && haystack.includes(needle));
  }

  function factHtml(fact, incidentSummary = "") {
    const access = ({ phishing: "Phishing", compromised_credentials: "Identifiants compromis", vulnerability_exploitation: "Exploitation d’une vulnérabilité", remote_access: "Accès distant", third_party: "Tiers compromis", malware: "Malware", other: "Autre" })[fact.initial_access] || fact.initial_access || "";
    const claimStatus = ({ claimed: "Revendiqué", confirmed: "Confirmé", unconfirmed: "Non confirmé", denied: "Démenti" })[fact.claim_status] || fact.claim_status || "";
    const impactCovered = narrativeContains(fact.summary, fact.impact) || narrativeContains(incidentSummary, fact.impact);
    const sourceImpact = impactCovered ? "" : fact.impact;
    const rows = [
      factRow("Statut", claimStatus), factRow("Acteur", fact.threat_actor), factRow("Tiers impliqué", fact.third_party),
      factRow("Vecteur d'entrée", access), factRow("Déroulé", attackFlowLabel(fact.attack_flow)), factRow("Localisation précise", fact.fine_location),
      factRow("Données touchées", duplicatesDedicatedFileCount(fact) ? "" : affectedLabel(fact)), factRow("Volume", fact.data_volume),
      factRow("Fichiers", fact.file_count != null ? formatNumber(fact.file_count) : ""), renderDataTypes(fact.data_types), renderRichFacts(fact.rich_facts),
      factRow("Vulnérabilités", Array.isArray(fact.vulnerabilities) ? fact.vulnerabilities.join(", ") : ""), factRow("CVSS", fact.cvss),
      factRow("Date d'attaque", fact.attack_date ? formatDate(fact.attack_date) : ""), factRow("Découverte", fact.discovered_date ? formatDate(fact.discovered_date) : ""),
      factRow("Score cyberattaque", fact.cyberattack_score != null ? `${fact.cyberattack_score}/100` : ""), factRow("Impact", sourceImpact), factRow("Évolution", fact.evolution),
    ].filter(Boolean);
    const links = [safeUrl(fact.victim_website), ...(fact.evidence_urls || []).map(safeUrl)].filter(Boolean).slice(0, 4);
    if (links.length) rows.push(`<div class="evidence-links">${links.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>`);
    return rows.length ? `<div class="incident-fact"><div class="incident-fact-source">${esc(sourceLabel(fact.source))}</div>${rows.join("")}</div>` : "";
  }

  function factsSectionHtml(incident, facts) {
    const parts = [];
    if (incident.summary) parts.push(`<div class="dialog-summary"><strong>Synthèse</strong><p>${esc(incident.summary)}</p></div>`);
    const rendered = (facts || []).map((fact) => factHtml(fact, incident.summary)).filter(Boolean);
    if (rendered.length) parts.push(`<div class="dialog-facts"><h3>Éléments documentés</h3>${rendered.join("")}</div>`);
    if (incident.local) {
      const references = (incident.local.references || []).map(safeUrl).filter(Boolean).slice(0, 4);
      parts.push(`<div class="local-analysis"><span class="local-score">Score cyberattaque : ${esc(incident.local.score)}/100</span><p><strong>Analyse locale :</strong> ${esc(incident.local.summary || "—")}</p>${references.length ? `<div class="evidence-links">${references.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>` : ""}</div>`);
    }
    return parts.length ? parts.join("") : '<p class="muted">Aucun enrichissement supplémentaire disponible.</p>';
  }

  function provenanceLabel(incident) {
    const count = new Set(incident.sources || []).size;
    if (count > 1) return `${count} sources · corroboré`;
    return count === 1 ? "1 source · mono-source" : "source non documentée";
  }

  function sourceBadges(incident) {
    const homes = new Map();
    (state.status?.sources || []).forEach((source) => { const url = safeUrl(source.url); if (url) homes.set(source.id, url); });
    return (incident.sources || []).map((id) => {
      const label = sourceLabel(id);
      const url = homes.get(id);
      return url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>` : `<span>${esc(label)}</span>`;
    }).join("");
  }

  // -------------------------------------------------------------- faits différés

  function ensureFacts() {
    if (state.factsPromise) return state.factsPromise;
    state.factsPromise = load("assets/data/facts.json", {}).then((result) => {
      state.facts = result.ok && result.data && typeof result.data === "object" ? result.data : {};
      if (!result.ok) reportDataFailure("assets/data/facts.json");
      return state.facts;
    });
    return state.factsPromise;
  }

  // ------------------------------------------------------------------ dialogue

  let lastFocused = null;

  async function openIncident(id) {
    const incident = state.byId.get(id);
    if (!incident) return;
    lastFocused = document.activeElement;
    const facts = await ensureFacts();
    const links = Array.from(new Set((incident.urls || []).map(safeUrl).filter(Boolean)));
    $("#detail-dialog-content").innerHTML = `
      <p class="eyebrow">Incident</p><h2 id="detail-dialog-title">${esc(incident.org || "Organisation inconnue")}${sensitivityHtml(incident)}</h2>
      <div class="detail-grid">
        <div><span>Date</span><strong>${esc(formatDate(incident.date))}</strong><small>${esc(incident.basis === "EVENT" ? "date d’événement" : "date de publication")}</small></div>
        <div><span>Menace</span><strong>${esc(incident.threat || "Inconnu")}</strong></div>
        <div><span>Secteur</span><strong>${esc(incident.sector || "Inconnu")}</strong></div>
        <div><span>Territoire</span><strong>${esc(incident.location || "Inconnu")}</strong></div>
        <div><span>Première observation</span><strong>${esc(formatDateTime(incident.first_seen))}</strong></div>
        <div><span>Dernière observation</span><strong>${esc(formatDateTime(incident.last_seen))}</strong></div>
      </div>
      <p class="dialog-summary"><strong>${esc(provenanceLabel(incident))}</strong> · ${esc((incident.sources || []).map(sourceLabel).join(" · ") || "—")}</p>
      ${links.length ? `<div class="dialog-evidence"><strong>Références</strong>${links.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(host(url))}</a>`).join("")}</div>` : ""}
      ${factsSectionHtml(incident, facts[id])}`;
    $("#detail-dialog-back").hidden = true;
    const dialog = $("#detail-dialog");
    dialog.showModal();
  }

  function openOrganisation(name) {
    const key = normalize(name);
    const rows = Array.from(state.byId.values())
      .filter((row) => normalize(row.org) === key)
      .sort((a, b) => String(b.date).localeCompare(String(a.date)));
    if (!rows.length) return;
    lastFocused = document.activeElement;
    const threats = countBy(rows, "threat");
    const sources = Array.from(new Set(rows.flatMap((row) => row.sources || []))).sort((a, b) => sourceLabel(a).localeCompare(sourceLabel(b), "fr")).map(sourceLabel);
    $("#detail-dialog-content").innerHTML = `
      <p class="eyebrow">Organisation</p><h2 id="detail-dialog-title">${esc(name)}</h2>
      <div class="detail-grid">
        <div><span>Incidents</span><strong>${rows.length}</strong></div>
        <div><span>Premier incident observé</span><strong>${esc(formatDate(rows[rows.length - 1].date))}</strong></div>
        <div><span>Dernier incident observé</span><strong>${esc(formatDate(rows[0].date))}</strong></div>
      </div>
      <p class="dialog-summary"><strong>Sources</strong> ${esc(sources.join(" · ") || "—")}</p>
      <div class="dialog-summary"><strong>Menaces observées</strong><p>${esc(threats.map((row) => `${row.label} (${row.value})`).join(" · "))}</p></div>
      <div class="org-history"><h3>Chronologie</h3>${rows.map((row) => `<button type="button" class="org-history-row" data-id="${esc(row.id)}"><time>${esc(formatDate(row.date))}</time><span>${esc(row.threat || "Inconnu")}</span><small>${esc(row.location || "Inconnu")}</small></button>`).join("")}</div>`;
    $("#detail-dialog-back").hidden = true;
    $("#detail-dialog").showModal();
  }

  function bindDialog() {
    const dialog = $("#detail-dialog");
    dialog.addEventListener("close", () => { if (lastFocused && document.contains(lastFocused)) lastFocused.focus(); });
    $("#detail-dialog-content").addEventListener("click", (event) => {
      const orgLink = event.target.closest("[data-org-link]");
      if (orgLink) return openOrganisation(orgLink.dataset.orgLink);
      const historyRow = event.target.closest(".org-history-row");
      if (historyRow) return openIncident(historyRow.dataset.id);
    });
  }

  // ----------------------------------------------------------------- routage

  function readUrl() {
    const params = new URLSearchParams(location.search);
    state.view = VIEWS.includes(params.get("vue")) ? params.get("vue") : "veille";
    state.filters.q = params.get("q") || "";
    state.filters.threat = params.get("threat") || "";
    state.filters.sector = params.get("sector") || "";
    state.filters.location = params.get("location") || "";
    state.filters.source = params.get("source") || "";
    state.filters.period = params.get("period") || "all";
    state.sort = params.get("sort") || "date-desc";
    state.page = Math.max(1, Number(params.get("page")) || 1);
  }

  function syncUrl(push) {
    const params = new URLSearchParams();
    if (state.view !== "veille") params.set("vue", state.view);
    if (state.view === "recherche") {
      Object.entries(state.filters).forEach(([key, value]) => { if (value && value !== "all") params.set(key, value); });
      if (state.sort !== "date-desc") params.set("sort", state.sort);
      if (state.page > 1) params.set("page", String(state.page));
    }
    const query = params.toString();
    const url = `${location.pathname}${query ? `?${query}` : ""}`;
    if (push) history.pushState(null, "", url); else history.replaceState(null, "", url);
  }

  function goToView(view, { push = true } = {}) {
    state.view = view;
    syncUrl(push);
    render();
  }

  // ------------------------------------------------------------------- rendu

  function render() {
    $$(".views button").forEach((button) => button.setAttribute("aria-current", String(button.dataset.view === state.view)));
    $$(".view").forEach((section) => { section.hidden = section.id !== `view-${state.view}`; });
    if (state.view === "veille") renderVeille();
    else if (state.view === "recherche") renderRecherche();
    else renderAnalyse();
  }

  // ------------------------------------------------------------------ veille

  function renderVeille() {
    if (!state.dataOk) {
      $("#freshness").textContent = "Données indisponibles.";
      $("#change-line").textContent = "";
      $("#focus-body").innerHTML = "";
      $("#veille-list").innerHTML = '<p class="empty-state">Données indisponibles — cette absence n’indique aucun incident, ni son contraire.</p>';
      $("#veille-count").textContent = "";
      return;
    }
    const run = state.status?.run || {};
    const counts = state.status?.counts || { ok: 0, partial: 0, fail: 0, skipped: 0 };
    const total = (state.status?.sources || []).length || counts.ok + counts.partial + counts.fail + counts.skipped;
    $("#freshness").innerHTML = state.statusOk
      ? `Données arrêtées au <strong>${esc(formatDateTime(run.as_of))}</strong> · <strong>${counts.ok}/${total}</strong> sources opérationnelles`
      : "État des sources indisponible.";

    const a = state.analytics;
    const changeLine = $("#change-line");
    if (a) {
      changeLine.innerHTML = `${esc(a.briefing[0])} <button type="button" class="btn-link" data-goto="analyse">Voir l’analyse complète →</button>`;
    } else {
      changeLine.textContent = "";
    }

    renderFocusBlock($("#focus-body"), a?.focus, { withList: true });

    const rows = state.latestRows;
    $("#veille-count").textContent = rows.length ? `${formatNumber(rows.length)} incident${plural(rows.length, "", "s")} publiquement observés sur 30 jours` : "Aucun incident sur 30 jours.";
    $("#veille-list").innerHTML = rows.length
      ? rows.map((incident) => incidentCardHtml(incident)).join("")
      : '<p class="empty-state">Aucun incident publiquement observé sur les 30 derniers jours — dans les sources couvertes.</p>';
  }

  function renderFocusBlock(container, focus, { withList = false } = {}) {
    if (!focus || !focus.locations || !focus.locations.length) { container.innerHTML = ""; return; }
    const byLocation = Object.entries(focus.by_location || {}).map(([label, value]) => `${label} ${value}`).join(" · ");
    const parts = [`<p class="focus-stats"><strong>${formatNumber(focus.incidents)}</strong> incident${plural(focus.incidents, "", "s")} (${focus.share_pct} % de la base) — ${esc(byLocation)}</p>`];
    if (focus.last_date) {
      const label = focus.silence_is_unusual
        ? `Aucun incident publiquement observé depuis <strong>${focus.days_since_last} jour${plural(focus.days_since_last, "", "s")}</strong> — au-delà de l’écart maximal observé (${focus.max_gap_days} j). Ce silence est inhabituel au regard de l’historique.`
        : `Dernier incident : ${esc(formatDate(focus.last_date))}, il y a ${focus.days_since_last} jour${plural(focus.days_since_last, "", "s")} — conforme à la normale observée (écart médian ${focus.median_gap_days} j, maximum ${focus.max_gap_days} j).`;
      parts.push(`<p class="focus-note" data-unusual="${focus.silence_is_unusual}">${label}</p>`);
    } else {
      parts.push('<p class="focus-note">Aucun incident publiquement observé sur ce périmètre à ce jour.</p>');
    }
    parts.push(`<p class="focus-note">${focus.multi_source}/${focus.incidents} incident${plural(focus.incidents, "", "s")} corroboré${plural(focus.multi_source, "", "s")} par plusieurs sources.</p>`);
    if (withList) {
      const localRows = state.latestRows.filter((row) => (focus.locations || []).includes(row.location));
      parts.push(localRows.length
        ? `<div class="focus-list">${localRows.map((row) => focusItemHtml(row)).join("")}</div>`
        : '<p class="focus-empty">Aucun incident sur ce périmètre dans les 30 derniers jours.</p>');
    }
    container.innerHTML = parts.join("");
    if (withList) {
      container.querySelectorAll("[data-open-id]").forEach((el) => el.addEventListener("click", () => openIncident(el.dataset.openId)));
    }
  }

  function focusItemHtml(row) {
    const score = row.local ? `<span class="chip" data-status="OK">Score local ${esc(row.local.score)}/100</span>` : "";
    const summary = row.summary || row.local?.summary || "";
    return `<button type="button" class="focus-item" data-open-id="${esc(row.id)}" style="text-align:left;cursor:pointer;width:100%;border:1px solid var(--border);background:var(--surface);color:inherit;font:inherit">
      <div class="focus-item-head"><span class="focus-item-org">${esc(row.org || "Organisation inconnue")}</span><time>${esc(formatDate(row.date))} · ${esc(row.location)}</time></div>
      <div>${esc(row.threat || "Inconnu")} ${score}</div>
      ${summary ? `<p class="summary">${esc(summary)}</p>` : ""}
    </button>`;
  }

  function incidentCardHtml(incident) {
    return `<article class="incident-card" data-id="${esc(incident.id)}">
      <div>
        <div class="incident-card-top"><time datetime="${esc(incident.date)}">${esc(formatDate(incident.date))}</time><span>${esc(incident.location || "Inconnu")}</span></div>
        <button type="button" class="incident-org-link" data-open-org="${esc(incident.org)}">${esc(incident.org || "Organisation inconnue")}</button>
        <p class="incident-tags"><span>${esc(incident.threat || "Inconnu")}</span><span>${esc(incident.sector || "Inconnu")}</span></p>
        ${incident.summary ? `<p class="incident-summary-text">${esc(incident.summary)}</p>` : ""}
      </div>
      <div class="incident-side">
        <span class="incident-provenance">${esc(provenanceLabel(incident))}</span>
        <div class="incident-source-badges">${sourceBadges(incident)}</div>
        <button type="button" class="btn btn-primary" data-open-id="${esc(incident.id)}">Voir l’incident</button>
      </div>
    </article>`;
  }

  function bindIncidentListClicks(root) {
    root.addEventListener("click", (event) => {
      const openBtn = event.target.closest("[data-open-id]");
      if (openBtn) return openIncident(openBtn.dataset.openId);
      const orgBtn = event.target.closest("[data-open-org]");
      if (orgBtn) return openOrganisation(orgBtn.dataset.openOrg);
    });
  }

  // --------------------------------------------------------------- recherche

  function uniqueSorted(values) {
    return Array.from(new Set(values.filter((value) => value && value !== "Inconnu"))).sort((a, b) => a.localeCompare(b, "fr"));
  }

  function setOptions(select, values, allLabel, format = (value) => value) {
    const current = select.value;
    select.innerHTML = `<option value="">${esc(allLabel)}</option>` + values.map((value) => `<option value="${esc(value)}">${esc(format(value))}</option>`).join("");
    select.value = values.includes(current) ? current : "";
  }

  function populateSearchOptions() {
    const rows = state.incidentsRows;
    setOptions($("#s-threat"), uniqueSorted(rows.map((row) => row.threat)), "Toutes");
    setOptions($("#s-sector"), uniqueSorted(rows.map((row) => row.sector)), "Tous");
    setOptions($("#s-location"), uniqueSorted(rows.map((row) => row.location)), "Tous");
    setOptions($("#s-source"), uniqueSorted(rows.flatMap((row) => row.sources || [])), "Toutes", sourceLabel);
    syncSearchControls();
  }

  function syncSearchControls() {
    $("#s-q").value = state.filters.q;
    $("#s-threat").value = state.filters.threat;
    $("#s-sector").value = state.filters.sector;
    $("#s-location").value = state.filters.location;
    $("#s-source").value = state.filters.source;
    $("#s-period").value = state.filters.period;
    $("#s-sort").value = state.sort;
  }

  function cutoffFor(period) {
    const days = Number(period);
    return Number.isFinite(days) && days > 0 ? new Date(Date.now() - days * DAY) : null;
  }

  function filteredSearch() {
    const query = normalize(state.filters.q);
    const cutoff = cutoffFor(state.filters.period);
    return state.incidentsRows.filter((incident) => {
      if (query && !(state.searchIndex.get(incident) || "").includes(query)) return false;
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

  function sortedSearch(rows) {
    const result = rows.slice();
    if (state.sort === "date-asc") return result.sort((a, b) => String(a.date).localeCompare(String(b.date)));
    if (state.sort === "org") return result.sort((a, b) => String(a.org).localeCompare(String(b.org), "fr"));
    if (state.sort === "sources") return result.sort((a, b) => (b.sources?.length || 0) - (a.sources?.length || 0));
    return result.sort((a, b) => String(b.date).localeCompare(String(a.date)));
  }

  function renderActiveFilters() {
    const labels = [];
    if (state.filters.q) labels.push(`Recherche : “${state.filters.q}”`);
    if (state.filters.threat) labels.push(`Menace : ${state.filters.threat}`);
    if (state.filters.sector) labels.push(`Secteur : ${state.filters.sector}`);
    if (state.filters.location) labels.push(`Territoire : ${state.filters.location}`);
    if (state.filters.source) labels.push(`Source : ${sourceLabel(state.filters.source)}`);
    if (state.filters.period !== "all") labels.push(`Période : ${state.filters.period} jours`);
    $("#s-active-filters").innerHTML = labels.length ? labels.map((label) => `<span>${esc(label)}</span>`).join("") : '<span class="muted">Aucun filtre actif.</span>';
  }

  function renderRecherche() {
    syncSearchControls();
    renderActiveFilters();
    if (!state.dataOk) {
      $("#s-count").textContent = "Données indisponibles.";
      $("#s-list").innerHTML = '<p class="empty-state">Données indisponibles.</p>';
      $("#s-pager").innerHTML = "";
      return;
    }
    if (!state.incidentsLoaded) {
      if (state.incidentsFailed) {
        $("#s-count").textContent = "Données indisponibles.";
        $("#s-list").innerHTML = '<p class="empty-state">La base complète n’a pas pu être chargée — cette absence n’indique aucun incident, ni son contraire.</p>';
        $("#s-pager").innerHTML = "";
        return;
      }
      $("#s-count").textContent = "Chargement de la base complète…";
      $("#s-list").innerHTML = '<p class="empty-state">Chargement de la base complète des incidents…</p>';
      $("#s-pager").innerHTML = "";
      loadIncidentsInBackground();
      return;
    }
    const filtered = filteredSearch();
    const ordered = sortedSearch(filtered);
    const pages = Math.max(1, Math.ceil(ordered.length / state.pageSize));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * state.pageSize;
    const shown = ordered.slice(start, start + state.pageSize);
    const corroborated = filtered.length ? Math.round(100 * filtered.filter((row) => new Set(row.sources || []).size > 1).length / filtered.length) : 0;
    $("#s-count").textContent = filtered.length
      ? `${formatNumber(filtered.length)} incident${plural(filtered.length, "", "s")} · ${corroborated} % corroborés · ${start + 1}–${Math.min(start + shown.length, ordered.length)} affichés`
      : "0 incident";
    $("#s-list").innerHTML = shown.length ? shown.map((incident) => incidentCardHtml(incident)).join("") : '<div class="empty-state"><strong>Aucun résultat.</strong><p>Élargissez les filtres ou réinitialisez la recherche.</p></div>';
    $("#s-pager").innerHTML = `<button type="button" data-page="prev" class="btn" ${state.page <= 1 ? "disabled" : ""}>Précédent</button><span>Page ${state.page} / ${pages}</span><button type="button" data-page="next" class="btn" ${state.page >= pages ? "disabled" : ""}>Suivant</button>`;
  }

  function bindRecherche() {
    let timer;
    $("#s-q").addEventListener("input", (event) => {
      clearTimeout(timer);
      const value = event.target.value;
      timer = setTimeout(() => { state.filters.q = value; state.page = 1; syncUrl(true); render(); }, 200);
    });
    ["threat", "sector", "location", "source", "period"].forEach((key) => {
      $(`#s-${key}`).addEventListener("change", (event) => { state.filters[key] = event.target.value; state.page = 1; syncUrl(true); render(); });
    });
    $("#s-sort").addEventListener("change", (event) => { state.sort = event.target.value; state.page = 1; syncUrl(true); render(); });
    $("#s-reset").addEventListener("click", () => {
      state.filters = { q: "", threat: "", sector: "", location: "", source: "", period: "all" };
      state.sort = "date-desc"; state.page = 1; syncUrl(true); render();
    });
    $("#s-copy-link").addEventListener("click", async (event) => {
      syncUrl(true);
      try { await navigator.clipboard.writeText(location.href); event.target.textContent = "Lien copié"; }
      catch (_) { event.target.textContent = "URL prête à partager"; }
      setTimeout(() => { event.target.textContent = "Copier le lien de cette vue"; }, 1800);
    });
    $("#s-pager").addEventListener("click", (event) => {
      const button = event.target.closest("[data-page]");
      if (!button) return;
      state.page += button.dataset.page === "next" ? 1 : -1;
      syncUrl(false);
      render();
      $("#s-count").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    bindIncidentListClicks($("#view-recherche"));
  }

  // ----------------------------------------------------------------- analyse

  function switchToSearch(patch) {
    state.filters = { q: "", threat: "", sector: "", location: "", source: "", period: "all", ...patch };
    state.sort = "date-desc";
    state.page = 1;
    goToView("recherche");
  }

  function renderAnalyse() {
    const a = state.analytics;
    if (!a || !state.statusOk) {
      $("#reading-line").textContent = "Analyse indisponible : les indicateurs sont calculés côté serveur et publiés dans status.json.";
      return;
    }
    const q = a.quality;
    $("#reading-line").innerHTML = `<strong>${formatNumber(q.incidents)}</strong> incidents · <strong>${formatNumber(q.organisations)}</strong> organisations · <strong>${q.corroborated_pct} %</strong> corroborés · ${q.sources} source${plural(q.sources, "", "s")} · ${esc(formatDate(q.first_date))} → ${esc(formatDate(q.last_date))} (${q.history_months} mois)`;

    renderEvolution(a.series);
    barChartHorizontal($("#chart-threat"), (a.top_90d.threat || []).map((row) => ({ label: row.label, value: row.count })), { onSelect: (label) => switchToSearch({ threat: label, period: "90" }) });
    barChartHorizontal($("#chart-sector"), (a.top_90d.sector || []).map((row) => ({ label: row.label, value: row.count })), { onSelect: (label) => switchToSearch({ sector: label, period: "90" }) });
    $("#threat-note").textContent = `${a.coverage.threat.known_pct} % documentées.`;
    $("#sector-note").textContent = `${a.coverage.sector.known_pct} % documentés (dimension la moins couverte).`;

    renderSignals(a.signals, a.method);
    renderOcean(a.focus, a.ocean);
    renderExposure(a.exposure);
    renderQuality(a.quality);
    renderCite(a.quality, state.status.run);
    renderSourcesDetail();
  }

  function renderEvolution(series) {
    if (!series || !series.months.length) { emptyChart($("#chart-evolution")); $("#evolution-dimensions").innerHTML = ""; return; }
    barChartTime($("#chart-evolution"), series.months.map((month, index) => ({ label: monthLabel(month), value: series.total[index] })));
    const futureNote = series.excluded_future ? ` ${formatNumber(series.excluded_future)} incident${plural(series.excluded_future, "", "s")} à date future écarté${plural(series.excluded_future, "", "s")} de la série.` : "";
    $("#evolution-note").textContent = `Sources actives par mois : ${series.sources_observed.join(" → ")}. Une part qui monte peut être une source qui vient d’être ajoutée, pas une menace qui progresse.${futureNote}`;
    const container = $("#evolution-dimensions");
    container.innerHTML = "";
    container.appendChild(sparklineRow(series.months, series.sources_observed, "Sources actives"));
    Object.entries(series.threat || {}).slice(0, 3).forEach(([label, values]) => container.appendChild(sparklineRow(series.months, values, label)));
    Object.entries(series.sector || {}).slice(0, 3).forEach(([label, values]) => container.appendChild(sparklineRow(series.months, values, label)));
  }

  function signalMeta(signal) {
    const base = signal.base_rate_pct != null ? ` · part ${signal.share_pct} % de la fenêtre, taux de base ${signal.base_rate_pct > 0 ? "+" : ""}${signal.base_rate_pct} %` : "";
    return `${signal.current} incidents vs ${signal.previous} · Δ +${signal.delta}${base}`;
  }

  function renderSignals(signals, method) {
    const container = $("#signals-list");
    if (!signals || !signals.length) {
      container.innerHTML = '<p class="empty-state">Aucun signal ne dépasse les seuils conservateurs sur cette période.</p>';
    } else {
      const kindLabel = { emerging: "Émergence", acceleration: "Accélération", new_pair: "Nouveau couple" };
      container.innerHTML = signals.slice(0, 12).map((signal) => `
        <button type="button" class="signal" data-dimension="${esc(signal.dimension)}" data-label="${esc(signal.label)}">
          <span class="signal-kind">${esc(kindLabel[signal.kind] || signal.kind)} · ${signal.window_days} j</span>
          <strong>${esc(signal.label)}</strong>
          <span class="signal-meta">${esc(signalMeta(signal))}</span>
          <span class="signal-confidence" data-level="${esc(signal.confidence.level)}">Confiance ${esc({ high: "élevée", medium: "moyenne", low: "faible" }[signal.confidence.level] || signal.confidence.level)} · ${signal.confidence.score}/100</span>
        </button>`).join("");
      container.querySelectorAll(".signal").forEach((button) => button.addEventListener("click", () => {
        const dimension = button.dataset.dimension;
        const label = button.dataset.label;
        if (dimension === "threat_sector") { const [threat, sector] = label.split(" × "); return switchToSearch({ threat, sector }); }
        return switchToSearch({ [dimension]: label });
      }));
    }
    $("#signals-method").textContent = method ? `${method.signal_rule} ${method.base_rate} ${method.confidence}.` : "";
  }

  function oceanBlockHtml(profile, label) {
    if (!profile || !profile.incidents) return `<p class="muted">Aucun incident publiquement observé — ${esc(label)}.</p>`;
    const threats = (profile.threats || []).map((row) => `${row.label} (${row.count})`).join(" · ") || "—";
    const sourceMix = Object.entries(profile.by_source || {}).map(([id, count]) => `${sourceLabel(id)} ${count}`).join(" · ");
    const reliability = profile.threat_profile_reliable
      ? `<p class="muted">Profil de menace jugé lisible (${profile.incidents} incidents, source la plus présente ${profile.dominant_source_pct} %).</p>`
      : `<p class="focus-note" data-unusual="true">Échantillon trop petit ou dominé par une seule source (${profile.dominant_source_pct} % via ${esc(sourceMix)}) : ce profil de menace reflète la couverture, pas nécessairement le terrain.</p>`;
    return `<p><strong>${formatNumber(profile.incidents)}</strong> incidents · ${esc(threats)}</p>${reliability}`;
  }

  function renderOcean(focus, ocean) {
    $("#ocean-focus").innerHTML = oceanBlockHtml(focus?.profile, "La Réunion / Mayotte");
    $("#ocean-ensemble").innerHTML = oceanBlockHtml(ocean?.profile, "l’ensemble Océan Indien");
    $("#ocean-caveat").textContent = ocean && ocean.incidents
      ? `Échantillon réduit (n = ${ocean.incidents}, ${ocean.share_pct} % de la base) : à lire comme une observation, pas une statistique robuste.`
      : "";
  }

  function renderExposure(exposure) {
    const box = $("#exposure-body");
    if (!exposure || !exposure.documented) {
      box.innerHTML = '<p class="muted">Aucun volume documenté sur la base actuelle.</p>';
      return;
    }
    const evidence = Object.entries(exposure.evidence || {}).map(([status, count]) => `<span>${esc({ confirmed: "confirmés", reported: "rapportés", claimed: "revendiqués", unknown: "non établis" }[status] || status)} : ${count}</span>`).join("");
    box.innerHTML = `
      <div class="indicator-grid">
        <div class="indicator"><strong>${formatNumber(exposure.median)}</strong><span>médiane</span></div>
        <div class="indicator"><strong>${formatNumber(exposure.p90)}</strong><span>90ᵉ centile</span></div>
        <div class="indicator"><strong>${exposure.documented}/${exposure.total}</strong><span>incidents avec volume (${exposure.documented_pct} %)</span></div>
      </div>
      <div class="evidence-breakdown">${evidence}</div>
      <p class="hint">${esc(exposure.note)}</p>`;
  }

  function renderQuality(quality) {
    const unknown = Object.entries(quality.unknown_pct || {}).map(([key, pct]) => `<span>${esc({ threat: "menace", sector: "secteur", location: "territoire" }[key] || key)} inconnu : ${pct} %</span>`).join("");
    $("#quality-body").innerHTML = `
      <div class="indicator-grid">
        <div class="indicator"><strong>${quality.mono_source_pct} %</strong><span>mono-source</span></div>
        <div class="indicator"><strong>${quality.with_summary_pct} %</strong><span>avec synthèse</span></div>
        <div class="indicator"><strong>${quality.sources}</strong><span>sources actives</span></div>
        <div class="indicator"><strong>${quality.history_months}</strong><span>mois d’historique</span></div>
      </div>
      <div class="evidence-breakdown">${unknown}</div>`;
  }

  function renderCite(quality, run) {
    const text = `Cyberwatch, données arrêtées au ${formatDate(run?.as_of)} : ${formatNumber(quality.incidents)} incidents cyber publiquement documentés en France et dans l’Océan Indien (${quality.sources} sources, ${quality.corroborated_pct} % corroborés). ${location.origin}${location.pathname}`;
    $("#cite-box").textContent = text;
    $("#cite-copy").onclick = async () => {
      try { await navigator.clipboard.writeText(text); $("#cite-copy").textContent = "Copié"; }
      catch (_) { $("#cite-copy").textContent = "Texte prêt à copier"; }
      setTimeout(() => { $("#cite-copy").textContent = "Copier le texte"; }, 1800);
    };
  }

  function renderSourcesDetail() {
    const rows = state.status?.sources || [];
    $("#sources-leds").innerHTML = rows.map((source) => {
      const status = String(source.status || "SKIPPED").toUpperCase();
      const level = status === "OK" ? "ok" : status === "FAIL" ? "fail" : "attention";
      return `<span class="source-led-item"><span class="source-led source-led--${level}" role="img" aria-label="${esc(status)}"></span>${esc(sourceLabel(source.id))}</span>`;
    }).join("");
    $("#sources-detail-table tbody").innerHTML = rows.map((source) => {
      const status = String(source.status || "SKIPPED").toUpperCase();
      const historyStatus = String(source.history_status || "UNKNOWN").toUpperCase();
      const historyNote = historyStatus === "TRUNCATED" ? `<div class="muted">Historique borné${source.oldest_available_date ? ` depuis ${esc(formatDate(source.oldest_available_date))}` : ""}</div>` : "";
      return `<tr><td>${esc(sourceLabel(source.id))}</td><td><span class="chip" data-status="${esc(status)}">${esc(status)}</span>${historyNote}</td><td>${esc(formatDate(source.latest_item))}</td><td>${esc(source.latest_item_org || "—")}</td><td class="num">${esc(source.items_seen ?? "—")}</td><td class="num">${esc(source.items_in_window ?? "—")}</td></tr>`;
    }).join("");
    const spots = state.status?.blind_spots || [];
    const box = $("#blindspots");
    box.hidden = !spots.length;
    $("#blindspots-list").innerHTML = spots.map((spot) => `<li><strong>${esc(spot.id)}</strong> — ${esc(spot.status || "À vérifier")}${spot.coverage != null ? ` ${esc(spot.coverage)}%` : ""}${spot.detail ? ` (${esc(spot.detail)})` : ""}${spot.reason ? ` : ${esc(spot.reason)}` : ""}</li>`).join("");
  }

  function bindAnalyse() {
    bindIncidentListClicks($("#view-analyse"));
  }

  // -------------------------------------------------------------- pastille

  function renderRunPill() {
    const pill = $("#run-pill");
    const text = $("#run-pill-text");
    if (!state.statusOk) { pill.dataset.status = ""; text.textContent = "État des sources indisponible"; return; }
    const data = state.status;
    if (data?.initialized === false) { pill.dataset.status = ""; text.textContent = "Base non initialisée"; return; }
    if (!data?.run?.id) { pill.dataset.status = ""; text.textContent = "Aucune collecte"; return; }
    const counts = data.counts || { ok: 0, partial: 0, fail: 0, skipped: 0 };
    const total = (data.sources || []).length || counts.ok + counts.partial + counts.fail + counts.skipped;
    const needsAttention = (data.blind_spots || []).length;
    pill.dataset.status = data.run.overall;
    text.textContent = needsAttention ? `Sources : ${counts.ok}/${total} opérationnelles · ${needsAttention} à vérifier` : `Sources : ${counts.ok}/${total} opérationnelles`;
  }

  // ------------------------------------------------------------------ boot

  async function loadIncidentsInBackground() {
    if (state.incidentsLoading || state.incidentsLoaded) return;
    state.incidentsLoading = true;
    state.incidentsFailed = false;
    const result = await load("assets/data/incidents.json", []);
    state.incidentsLoading = false;
    if (!result.ok || !Array.isArray(result.data)) {
      state.incidentsFailed = true;
      reportDataFailure("assets/data/incidents.json");
      // La bannière signale déjà l'échec ; la vue Recherche, elle, ne doit pas
      // rester bloquée sur « chargement… » alors que le chargement s'est arrêté.
      if (state.view === "recherche") render();
      return;
    }
    state.incidentsRows = result.data;
    state.incidentsRows.forEach((row) => state.byId.set(row.id, row));
    state.searchIndex = buildSearchIndex(state.incidentsRows);
    state.incidentsLoaded = true;
    populateSearchOptions();
    if (state.view === "recherche") render();
  }

  function setupTheme() {
    const stored = localStorage.getItem("cyberwatch-theme");
    if (stored) document.documentElement.dataset.theme = stored;
    $("#theme-toggle").addEventListener("click", () => {
      const dark = document.documentElement.dataset.theme === "dark" || (!document.documentElement.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
      document.documentElement.dataset.theme = dark ? "light" : "dark";
      localStorage.setItem("cyberwatch-theme", document.documentElement.dataset.theme);
      if (state.view === "analyse") renderAnalyse();
    });
  }

  function setupResize() {
    let timer;
    let lastWidth = document.documentElement.clientWidth;
    addEventListener("resize", () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        const width = document.documentElement.clientWidth;
        if (Math.abs(width - lastWidth) <= 20) return;
        lastWidth = width;
        if (state.view === "analyse" && state.analytics) renderAnalyse();
      }, 220);
    });
  }

  function bindNav() {
    $$(".views button").forEach((button) => button.addEventListener("click", () => goToView(button.dataset.view)));
    document.addEventListener("click", (event) => {
      const goto = event.target.closest("[data-goto]");
      if (goto) goToView(goto.dataset.goto);
    });
    addEventListener("popstate", () => { readUrl(); render(); });
  }

  function bindVeille() {
    bindIncidentListClicks($("#view-veille"));
  }

  document.addEventListener("DOMContentLoaded", async () => {
    setupTheme();
    setupResize();
    bindNav();
    bindDialog();
    bindVeille();
    bindRecherche();
    bindAnalyse();

    const [statusResult, latestResult] = await Promise.all([
      load("assets/data/status.json", null),
      load("assets/data/latest.json", []),
    ]);
    state.statusOk = statusResult.ok;
    state.status = statusResult.data;
    state.dataOk = latestResult.ok && Array.isArray(latestResult.data);
    state.latestRows = Array.isArray(latestResult.data) ? latestResult.data : [];
    state.latestRows.forEach((row) => state.byId.set(row.id, row));

    if (state.status?.labels?.sources) setSourceLabels(state.status.labels.sources);
    state.analytics = state.status?.analytics || null;

    if (!state.dataOk) reportDataFailure("assets/data/latest.json");
    if (!state.statusOk) reportDataFailure("assets/data/status.json");

    renderRunPill();
    readUrl();
    render();

    loadIncidentsInBackground();
  });
})();
