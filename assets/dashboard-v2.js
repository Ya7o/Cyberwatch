/* Cyberwatch — UI dashboard v2: synthèse d'activité et harmonisation des dimensions. */
(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const OCEAN_LOCATIONS = new Set([
    "La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores",
  ]);
  const MONTHS = [
    "janv.", "févr.", "mars", "avr.", "mai", "juin",
    "juil.", "août", "sept.", "oct.", "nov.", "déc.",
  ];
  const UNKNOWN_VALUES = new Set([
    "", "inconnu", "inconnue", "unknown", "non renseigne", "non renseignee", "n/a", "na", "—", "-",
  ]);
  const DAY = 864e5;
  const SVG_NS = "http://www.w3.org/2000/svg";

  let incidents = [];
  let renderTimer = null;

  function normalize(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase("fr-FR")
      .trim();
  }

  function isKnown(value) {
    return !UNKNOWN_VALUES.has(normalize(value));
  }

  function incidentDate(incident) {
    const date = new Date(incident?.date);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" });
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString("fr-FR");
  }

  function currentFilters() {
    return {
      org: normalize($("#f-org")?.value),
      source: $("#f-source")?.value || "",
      ocean: $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true",
      local: $("#f-local")?.getAttribute("aria-pressed") === "true",
    };
  }

  function filteredRows() {
    const filters = currentFilters();
    return incidents.filter((incident) => {
      if (filters.source && !(incident.sources || []).includes(filters.source)) return false;
      if (filters.ocean && !OCEAN_LOCATIONS.has(incident.location)) return false;
      if (filters.local && !incident.local) return false;
      if (filters.org && !normalize(incident.org).includes(filters.org)) return false;
      return true;
    });
  }

  function countBetween(rows, start, end) {
    return rows.reduce((count, incident) => {
      const date = incidentDate(incident);
      return date && date >= start && date < end ? count + 1 : count;
    }, 0);
  }

  function renderActivity(rows) {
    const now = new Date();
    const end = new Date(now.getTime() + 1);
    const currentStart = new Date(now.getTime() - 30 * DAY);
    const previousStart = new Date(now.getTime() - 60 * DAY);
    const yearStart = new Date(now.getTime() - 365 * DAY);

    const current = countBetween(rows, currentStart, end);
    const previous = countBetween(rows, previousStart, currentStart);
    const year = countBetween(rows, yearStart, end);
    const currentNode = $("#kpi-30d");
    const trendNode = $("#kpi-30d-trend");
    const yearNode = $("#kpi-12m");

    if (currentNode) currentNode.textContent = formatNumber(current);
    if (yearNode) yearNode.textContent = formatNumber(year);
    if (!trendNode) return;

    if (previous === 0) {
      trendNode.textContent = current === 0 ? "Stable vs 30 jours précédents" : "Nouvelle activité vs 30 jours précédents";
      trendNode.dataset.direction = current === 0 ? "flat" : "up";
      return;
    }

    const percent = Math.round(((current - previous) / previous) * 100);
    const sign = percent > 0 ? "+" : "";
    trendNode.textContent = `${sign}${percent} % vs 30 jours précédents`;
    trendNode.dataset.direction = percent > 0 ? "up" : percent < 0 ? "down" : "flat";
  }

  function renderOceanAlert() {
    const now = new Date();
    const cutoff = new Date(now.getTime() - 30 * DAY);
    const recent = incidents
      .filter((incident) => OCEAN_LOCATIONS.has(incident.location))
      .map((incident) => ({ incident, date: incidentDate(incident) }))
      .filter((item) => item.date && item.date >= cutoff && item.date <= now)
      .sort((a, b) => b.date - a.date);

    const card = $("#ocean-alert");
    if (!card) return;
    card.hidden = recent.length === 0;
    if (!recent.length) return;

    $("#ocean-alert-count").textContent = formatNumber(recent.length);
    const latest = recent[0];
    const territory = isKnown(latest.incident.location) ? latest.incident.location : "zone Océan Indien";
    $("#ocean-alert-note").textContent = `${recent.length > 1 ? "incidents" : "incident"} dans les 30 derniers jours · Dernier : ${territory}, ${formatDate(latest.date)}`;
  }

  function countKnownBy(rows, key) {
    const counts = new Map();
    rows.forEach((row) => {
      const value = row[key];
      if (!isKnown(value)) return;
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    return Array.from(counts, ([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value || String(a.label).localeCompare(String(b.label), "fr"));
  }

  function setCoverageNote(rows, key, selector) {
    const node = $(selector);
    if (!node) return;
    if (!rows.length) {
      node.textContent = "";
      return;
    }
    const known = rows.filter((row) => isKnown(row[key])).length;
    node.textContent = `${formatNumber(known)} incidents sur ${formatNumber(rows.length)} documentés (${Math.round(100 * known / rows.length)} %).`;
  }

  function svgEl(name, attrs = {}, text = null) {
    const node = document.createElementNS(SVG_NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
    if (text !== null) node.textContent = text;
    return node;
  }

  function wrapChartLabel(value, maxChars, maxLines) {
    const words = String(value || "").trim().split(/\s+/).filter(Boolean);
    if (!words.length) return [""];

    const lines = [];
    let current = "";
    let index = 0;
    while (index < words.length && lines.length < maxLines) {
      const word = words[index];
      const candidate = current ? `${current} ${word}` : word;
      if (candidate.length <= maxChars || !current) {
        current = candidate;
        index += 1;
        continue;
      }
      lines.push(current);
      current = "";
    }
    if (current && lines.length < maxLines) lines.push(current);

    if (index < words.length && lines.length) {
      let last = lines[lines.length - 1];
      const ellipsis = "…";
      if (last.length >= maxChars) last = last.slice(0, Math.max(1, maxChars - 1)).trimEnd();
      lines[lines.length - 1] = `${last}${ellipsis}`;
    }
    return lines;
  }

  function renderHorizontalChart(container, data) {
    if (!container) return;
    container.innerHTML = "";
    if (!data.length) {
      container.innerHTML = '<p class="empty-chart">Aucun incident documenté sur la sélection.</p>';
      return;
    }

    let rows = data;
    if (data.length > 9) {
      const others = data.slice(8).reduce((sum, row) => sum + row.value, 0);
      rows = data.slice(0, 8).concat([{ label: "Autres", value: others }]);
    }

    const width = Math.max(container.clientWidth || 520, 280);
    const isMobile = width <= 700;
    const rowHeight = isMobile ? 44 : 32;
    const labelWidth = isMobile
      ? Math.min(180, Math.max(140, width * 0.48))
      : Math.min(190, Math.max(105, width * 0.34));
    const right = isMobile ? 36 : 42;
    const labelGap = 10;
    const height = rows.length * rowHeight + 12;
    const max = Math.max(...rows.map((row) => row.value), 1);
    const plotWidth = Math.max(72, width - labelWidth - right - 14);
    const svg = svgEl("svg", {
      viewBox: `0 0 ${width} ${height}`,
      width,
      height,
      role: "img",
      "aria-label": "Répartition des incidents",
    });

    const clipId = `chart-label-clip-${container.id || "dimension"}-${Math.random().toString(36).slice(2, 8)}`;
    const defs = svgEl("defs");
    const clipPath = svgEl("clipPath", { id: clipId });
    clipPath.appendChild(svgEl("rect", { x: 0, y: 0, width: Math.max(0, labelWidth - labelGap), height }));
    defs.appendChild(clipPath);
    svg.appendChild(defs);

    rows.forEach((row, index) => {
      const y = index * rowHeight + 6;
      const barWidth = Math.max(2, (row.value / max) * plotWidth);
      const maxChars = Math.max(10, Math.floor((labelWidth - labelGap) / (isMobile ? 6.7 : 7.1)));
      const labelLines = wrapChartLabel(row.label, maxChars, isMobile ? 2 : 1);
      const label = svgEl("text", {
        class: "category-label",
        x: 0,
        y: isMobile ? y + 13 : y + 16,
        "clip-path": `url(#${clipId})`,
      });
      labelLines.forEach((line, lineIndex) => {
        label.appendChild(svgEl("tspan", {
          x: 0,
          dy: lineIndex === 0 ? 0 : 14,
        }, line));
      });
      label.appendChild(svgEl("title", {}, row.label));
      svg.appendChild(label);

      const barY = isMobile ? y + 10 : y + 3;
      const bar = svgEl("rect", { class: "bar", x: labelWidth, y: barY, width: barWidth, height: 18, rx: 4 });
      bar.appendChild(svgEl("title", {}, `${row.label} : ${row.value} incident${row.value > 1 ? "s" : ""}`));
      svg.appendChild(bar);
      svg.appendChild(svgEl("text", {
        class: "value-label",
        x: Math.min(width - 4, labelWidth + barWidth + 7),
        y: barY + 13,
      }, String(row.value)));
    });
    container.appendChild(svg);
  }

  function monthRange(rows) {
    const keys = rows
      .map((row) => String(row.date || "").slice(0, 7))
      .filter((key) => /^\d{4}-\d{2}$/.test(key))
      .sort();
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

  function renderMonthChart(rows) {
    const container = $("#chart-month");
    if (!container) return;
    const months = monthRange(rows);
    const counts = new Map(months.map((key) => [key, 0]));
    rows.forEach((incident) => {
      const key = String(incident.date || "").slice(0, 7);
      if (counts.has(key)) counts.set(key, counts.get(key) + 1);
    });
    const data = months.map((key) => ({ label: key, value: counts.get(key) || 0 }));
    container.innerHTML = "";
    if (!data.length) {
      container.innerHTML = '<p class="empty-chart">Aucun incident sur la sélection.</p>';
      return;
    }

    const visibleWidth = Math.max(container.clientWidth || 520, 320);
    const width = Math.max(visibleWidth, data.length * 50 + 52);
    const height = 260;
    const margin = { top: 28, right: 8, bottom: 38, left: 34 };
    const plotWidth = width - margin.left - margin.right;
    const plotHeight = height - margin.top - margin.bottom;
    const max = Math.max(...data.map((row) => row.value), 1);
    const step = plotWidth / data.length;
    const barWidth = Math.max(5, Math.min(36, step - 8));
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": "Incidents par mois" });

    data.forEach((point, index) => {
      const barHeight = (point.value / max) * plotHeight;
      const x = margin.left + index * step + (step - barWidth) / 2;
      const y = margin.top + plotHeight - barHeight;
      if (point.value) {
        svg.appendChild(svgEl("rect", { class: "bar", x, y, width: barWidth, height: barHeight, rx: 4 }));
      }
      svg.appendChild(svgEl("text", {
        class: "month-value-label",
        x: margin.left + index * step + step / 2,
        y: Math.max(14, y - 7),
        "text-anchor": "middle",
      }, String(point.value)));
      const [year, month] = point.label.split("-");
      const label = `${MONTHS[Number(month) - 1]} ${year.slice(2)}`;
      svg.appendChild(svgEl("text", {
        class: "tick-label",
        x: margin.left + index * step + step / 2,
        y: height - 12,
        "text-anchor": "middle",
      }, label));
    });
    container.appendChild(svg);
  }

  function reorderIncidentRows() {
    const tbody = $("#incidents-table tbody");
    if (!tbody) return;
    const desired = ["Date", "Organisation", "Secteur", "Menace", "Territoire", "Sources"];
    tbody.querySelectorAll("tr.incident-row").forEach((row) => {
      const cells = Array.from(row.children);
      if (cells.length !== 6) return;
      const current = cells.map((cell) => cell.dataset.label);
      if (desired.every((label, index) => current[index] === label)) return;
      const byLabel = new Map(cells.map((cell) => [cell.dataset.label, cell]));
      desired.forEach((label) => {
        const cell = byLabel.get(label);
        if (cell) row.appendChild(cell);
      });
    });
  }

  function renameVeilleLabels(root = document) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((node) => {
      if (node.nodeValue && node.nodeValue.includes("veillellmReYt")) {
        node.nodeValue = node.nodeValue.replaceAll("veillellmReYt", "Veille IA");
      }
    });
  }

  function renderDimensions(rows) {
    renderHorizontalChart($("#chart-sector"), countKnownBy(rows, "sector"));
    renderHorizontalChart($("#chart-threat"), countKnownBy(rows, "threat"));
    renderHorizontalChart($("#chart-location"), countKnownBy(rows, "location"));
    setCoverageNote(rows, "sector", "#sector-note");
    setCoverageNote(rows, "threat", "#threat-note");
    setCoverageNote(rows, "location", "#location-note");
  }

  function renderEnhancements() {
    const rows = filteredRows();
    renderActivity(rows);
    renderOceanAlert();
    renderMonthChart(rows);
    renderDimensions(rows);
    reorderIncidentRows();
    renameVeilleLabels(document.body);
  }

  function scheduleRender(delay = 0) {
    clearTimeout(renderTimer);
    renderTimer = setTimeout(renderEnhancements, delay);
  }

  function installStyle() {
    const style = document.createElement("style");
    style.id = "dashboard-v2-css";
    style.textContent = `
      .kpis-overview{align-items:stretch}
      .kpi-activity{grid-column:span 2}
      .activity-grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(120px,.75fr);gap:22px;align-items:end}
      .activity-secondary{padding-left:22px;border-left:1px solid var(--border)}
      .activity-value{font-size:clamp(2rem,5vw,3.2rem);font-weight:750;line-height:1;margin:0 0 10px;color:var(--text-primary)}
      .activity-trend{margin:9px 0 0;font-size:13px;font-weight:650;color:var(--text-secondary)}
      .activity-trend[data-direction="up"]{color:var(--status-partial)}
      .activity-trend[data-direction="down"]{color:var(--status-ok)}
      .ocean-alert{border-width:2px}
      .ocean-alert h2{display:flex;align-items:center;gap:8px}
      .ocean-alert h2::before{content:"";width:9px;height:9px;border-radius:50%;background:var(--status-partial);flex:none}
      .chart-month-card{grid-column:1/-1}
      #chart-month{overflow-x:auto;overflow-y:hidden}
      .month-value-label{font-size:11px;font-weight:700;fill:var(--text-primary)}
      .chart-note{min-height:1.2em}
      @media(max-width:700px){
        .kpi-activity{grid-column:auto}
        .activity-grid{grid-template-columns:1fr;gap:14px}
        .activity-secondary{padding-left:0;padding-top:14px;border-left:0;border-top:1px solid var(--border)}
        .chart-month-card{grid-column:auto}
      }
    `;
    document.head.appendChild(style);
  }

  document.addEventListener("DOMContentLoaded", async () => {
    installStyle();
    try {
      const response = await fetch("assets/data/incidents.json", { cache: "no-cache" });
      incidents = response.ok ? await response.json() : [];
      if (!Array.isArray(incidents)) incidents = [];
    } catch (_) {
      incidents = [];
    }

    ["#f-ocean-indien", "#f-local", "#f-reset", "#theme-toggle"].forEach((selector) => {
      $(selector)?.addEventListener("click", () => scheduleRender(0));
    });
    $("#f-source")?.addEventListener("change", () => scheduleRender(0));
    $("#f-org")?.addEventListener("input", () => scheduleRender(230));

    const tbody = $("#incidents-table tbody");
    if (tbody) {
      new MutationObserver(() => {
        reorderIncidentRows();
        renameVeilleLabels(tbody);
        scheduleRender(20);
      }).observe(tbody, { childList: true, subtree: true });
    }
    const sources = $("#sources-list")?.parentElement;
    if (sources) {
      new MutationObserver(() => renameVeilleLabels(sources)).observe(sources, { childList: true, subtree: true });
    }

    let resizeTimer;
    addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(renderEnhancements, 260);
    });

    scheduleRender(0);
    setTimeout(renderEnhancements, 600);
  });
})();