/* Cyberwatch — dashboard statique.
   Aucune dépendance, aucun CDN : les graphiques sont du SVG écrit à la main et
   les agrégats sont recalculés à chaque changement de filtre, de sorte qu'un
   KPI ne puisse jamais contredire le filtre actif. */

(() => {
  "use strict";

  const MONTHS = ["janv.", "févr.", "mars", "avr.", "mai", "juin",
                  "juil.", "août", "sept.", "oct.", "nov.", "déc."];

  const state = {
    incidents: [],
    status: null,
    sort: { key: "date", dir: -1 },
  };

  //: Libellés courts du statut global, pour la pastille.
  const LABELS = { OK: "OK", BROKEN: "BROKEN" };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // ------------------------------------------------------------ utilitaires

  const esc = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));

  const monthKey = (date) => (date || "").slice(0, 7);

  function monthLabel(key) {
    const [year, month] = key.split("-");
    return `${MONTHS[Number(month) - 1]} ${year.slice(2)}`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value.slice(0, 10);
    return date.toLocaleDateString("fr-FR", {
      day: "2-digit", month: "short", year: "numeric",
    });
  }

  function countBy(rows, key, { dropUnknown = false } = {}) {
    const counts = new Map();
    for (const row of rows) {
      const value = row[key] || "Inconnu";
      if (dropUnknown && value === "Inconnu") continue;
      counts.set(value, (counts.get(value) || 0) + 1);
    }
    return Array.from(counts, ([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label, "fr"));
  }

  /** Note de couverture d'une dimension souvent inconnue.
   *
   * Le secteur n'est renseigné que lorsque le nom de l'organisation le révèle
   * ou que la source le fournit. Masquer « Inconnu » rend le graphique
   * lisible ; annoncer la part réellement documentée évite de laisser croire
   * que le graphique porte sur l'ensemble. */
  function knownNote(rows, key, singular) {
    const known = rows.filter((r) => (r[key] || "Inconnu") !== "Inconnu").length;
    if (!rows.length) return "";
    const share = Math.round((100 * known) / rows.length);
    return `${known} incident${known > 1 ? "s" : ""} sur ${rows.length} ont un `
      + `${singular} documenté (${share} %). Les autres sont exclus de ce graphique.`;
  }

  // ------------------------------------------------------------- graphiques

  const SVG_NS = "http://www.w3.org/2000/svg";

  function el(name, attrs = {}, text) {
    const node = document.createElementNS(SVG_NS, name);
    for (const [key, value] of Object.entries(attrs)) {
      node.setAttribute(key, String(value));
    }
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const tooltip = $("#tooltip");

  function bindTooltip(node, html) {
    node.addEventListener("mouseenter", (event) => {
      tooltip.innerHTML = html;
      tooltip.hidden = false;
      moveTooltip(event);
    });
    node.addEventListener("mousemove", moveTooltip);
    node.addEventListener("mouseleave", () => { tooltip.hidden = true; });
  }

  function moveTooltip(event) {
    const pad = 14;
    const rect = tooltip.getBoundingClientRect();
    let x = event.clientX + pad;
    let y = event.clientY + pad;
    if (x + rect.width > window.innerWidth - 8) x = event.clientX - rect.width - pad;
    if (y + rect.height > window.innerHeight - 8) y = event.clientY - rect.height - pad;
    tooltip.style.left = `${Math.max(8, x)}px`;
    tooltip.style.top = `${Math.max(8, y)}px`;
  }

  function emptyChart(container, message) {
    container.innerHTML = `<p class="empty-chart">${esc(message)}</p>`;
  }

  /** Barres verticales — une série, donc pas de légende : le titre la nomme. */
  function barChartTime(container, data, { unit = "incident" } = {}) {
    container.innerHTML = "";
    if (!data.length) return emptyChart(container, "Aucun incident sur la sélection.");

    const width = Math.max(container.clientWidth || 520, 320);
    const height = 240;
    const margin = { top: 14, right: 8, bottom: 34, left: 34 };
    const plotW = width - margin.left - margin.right;
    const plotH = height - margin.top - margin.bottom;
    const max = Math.max(...data.map((d) => d.value), 1);
    const step = plotW / data.length;
    const barW = Math.max(3, Math.min(38, step - 6));

    const svg = el("svg", {
      viewBox: `0 0 ${width} ${height}`, width, height,
      role: "img", "aria-label": `Répartition mensuelle, ${data.length} mois`,
    });

    ticks(max).forEach((value) => {
      const y = margin.top + plotH - (value / max) * plotH;
      svg.appendChild(el("line", {
        class: "grid-line", x1: margin.left, x2: width - margin.right, y1: y, y2: y,
      }));
      svg.appendChild(el("text", {
        class: "tick-label", x: margin.left - 7, y: y + 3.5, "text-anchor": "end",
      }, String(value)));
    });

    data.forEach((point, index) => {
      const barH = (point.value / max) * plotH;
      const x = margin.left + index * step + (step - barW) / 2;
      const y = margin.top + plotH - barH;

      if (point.value > 0) {
        svg.appendChild(el("rect", {
          class: "bar", x, y, width: barW, height: barH, rx: 4,
        }));
      }
      const hit = el("rect", {
        class: "bar-hit", x: margin.left + index * step, y: margin.top,
        width: step, height: plotH,
      });
      bindTooltip(hit, `<strong>${esc(monthLabel(point.label))}</strong>
        ${point.value} ${unit}${point.value > 1 ? "s" : ""}`);
      svg.appendChild(hit);

      // Un label sur trois au plus : jamais un nombre sous chaque barre.
      const every = Math.ceil(data.length / 8);
      if (index % every === 0 || index === data.length - 1) {
        svg.appendChild(el("text", {
          class: "tick-label", x: margin.left + index * step + step / 2,
          y: height - 12, "text-anchor": "middle",
        }, monthLabel(point.label)));
      }
    });

    svg.appendChild(el("line", {
      class: "axis-line", x1: margin.left, x2: width - margin.right,
      y1: margin.top + plotH, y2: margin.top + plotH,
    }));
    container.appendChild(svg);
  }

  /** Barres horizontales — comparaison de magnitude, une seule teinte. */
  function barChartH(container, data, { unit = "incident", max: cap = 9 } = {}) {
    container.innerHTML = "";
    if (!data.length) return emptyChart(container, "Aucun incident sur la sélection.");

    let rows = data;
    if (data.length > cap) {
      const head = data.slice(0, cap - 1);
      const rest = data.slice(cap - 1).reduce((sum, d) => sum + d.value, 0);
      rows = head.concat([{ label: "Autres", value: rest }]);
    }

    const width = Math.max(container.clientWidth || 520, 320);
    const rowH = 26;
    const height = rows.length * rowH + 16;
    const labelW = Math.min(190, Math.max(110, width * 0.36));
    const valueW = 44;
    const plotW = width - labelW - valueW;
    const max = Math.max(...rows.map((d) => d.value), 1);

    const svg = el("svg", {
      viewBox: `0 0 ${width} ${height}`, width, height,
      role: "img", "aria-label": "Répartition par catégorie",
    });

    rows.forEach((row, index) => {
      const y = index * rowH + 8;
      const barW = Math.max(row.value > 0 ? 3 : 0, (row.value / max) * plotW);

      svg.appendChild(el("text", {
        class: "tick-label", x: labelW - 10, y: y + rowH / 2 + 0.5,
        "text-anchor": "end", "dominant-baseline": "middle",
      }, row.label.length > 26 ? `${row.label.slice(0, 25)}…` : row.label));

      if (barW > 0) {
        svg.appendChild(el("rect", {
          class: "bar", x: labelW, y: y + 5, width: barW, height: rowH - 12, rx: 4,
        }));
      }
      svg.appendChild(el("text", {
        class: "value-label", x: labelW + barW + 8, y: y + rowH / 2 + 0.5,
        "dominant-baseline": "middle",
      }, String(row.value)));

      const hit = el("rect", {
        class: "bar-hit", x: 0, y, width, height: rowH,
      });
      bindTooltip(hit, `<strong>${esc(row.label)}</strong>
        ${row.value} ${unit}${row.value > 1 ? "s" : ""}`);
      svg.appendChild(hit);
    });

    container.appendChild(svg);
  }

  /** Deux séries groupées — Réunion vs Mayotte, avec légende obligatoire. */
  function groupedBars(container, months, seriesA, seriesB, labels) {
    container.innerHTML = "";
    if (!months.length) return emptyChart(container, "Aucun incident sur la sélection.");

    const legend = document.createElement("div");
    legend.className = "legend";
    legend.innerHTML =
      `<span><i style="background:var(--series-1)"></i>${esc(labels[0])}</span>
       <span><i style="background:var(--series-2)"></i>${esc(labels[1])}</span>`;
    container.appendChild(legend);

    const width = Math.max(container.clientWidth || 640, 320);
    const height = 250;
    const margin = { top: 14, right: 8, bottom: 34, left: 34 };
    const plotW = width - margin.left - margin.right;
    const plotH = height - margin.top - margin.bottom;
    const max = Math.max(...months.map((m) => Math.max(seriesA.get(m) || 0, seriesB.get(m) || 0)), 1);
    const step = plotW / months.length;
    // 2px de fond entre deux remplissages adjacents.
    const barW = Math.max(3, Math.min(16, (step - 8) / 2 - 1));

    const svg = el("svg", {
      viewBox: `0 0 ${width} ${height}`, width, height,
      role: "img", "aria-label": "Comparaison mensuelle Réunion et Mayotte",
    });

    ticks(max).forEach((value) => {
      const y = margin.top + plotH - (value / max) * plotH;
      svg.appendChild(el("line", {
        class: "grid-line", x1: margin.left, x2: width - margin.right, y1: y, y2: y,
      }));
      svg.appendChild(el("text", {
        class: "tick-label", x: margin.left - 7, y: y + 3.5, "text-anchor": "end",
      }, String(value)));
    });

    months.forEach((month, index) => {
      const groupX = margin.left + index * step + step / 2;
      [[seriesA, "bar", -1], [seriesB, "bar-2", 1]].forEach(([series, cls, side]) => {
        const value = series.get(month) || 0;
        if (value <= 0) return;
        const barH = (value / max) * plotH;
        const x = groupX + (side < 0 ? -barW - 1 : 1);
        svg.appendChild(el("rect", {
          class: cls, x, y: margin.top + plotH - barH, width: barW, height: barH, rx: 4,
        }));
      });

      const hit = el("rect", {
        class: "bar-hit", x: margin.left + index * step, y: margin.top,
        width: step, height: plotH,
      });
      bindTooltip(hit, `<strong>${esc(monthLabel(month))}</strong>
        ${esc(labels[0])} : ${seriesA.get(month) || 0}<br>
        ${esc(labels[1])} : ${seriesB.get(month) || 0}`);
      svg.appendChild(hit);

      const every = Math.ceil(months.length / 8);
      if (index % every === 0 || index === months.length - 1) {
        svg.appendChild(el("text", {
          class: "tick-label", x: groupX, y: height - 12, "text-anchor": "middle",
        }, monthLabel(month)));
      }
    });

    svg.appendChild(el("line", {
      class: "axis-line", x1: margin.left, x2: width - margin.right,
      y1: margin.top + plotH, y2: margin.top + plotH,
    }));
    container.appendChild(svg);
  }

  function ticks(max) {
    const target = 4;
    const raw = max / target;
    const magnitude = Math.pow(10, Math.floor(Math.log10(raw || 1)));
    const stepSize = Math.max(1, Math.ceil(raw / magnitude) * magnitude);
    const out = [];
    for (let value = 0; value <= max; value += stepSize) out.push(value);
    return out;
  }

  // --------------------------------------------------------- action rapide

  const AUTOMOTIVE_ORGS = new Set(["groupe courtois automobiles"]);
  const LARGE_RETAIL_ORGS = new Set([
    "auchan", "intermarché", "intermarché drive", "lidl", "magasins u",
    "système u", "super u",
  ]);

  function orgKey(value) {
    return String(value || "").trim().toLocaleLowerCase("fr-FR");
  }

function applyFilters(incidents) {
  const localOnly = $("#f-local")?.getAttribute("aria-pressed") === "true";
  const selectedSource = $("#f-source")?.value || "";
  return incidents.filter((incident) => {
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

function monthsRange(incidents) {
    const keys = incidents.map((i) => monthKey(i.date)).filter(Boolean);
    if (!keys.length) return [];
    const min = keys.reduce((a, b) => (a < b ? a : b));
    const max = keys.reduce((a, b) => (a > b ? a : b));
    const out = [];
    let [year, month] = min.split("-").map(Number);
    const [endYear, endMonth] = max.split("-").map(Number);
    while (year < endYear || (year === endYear && month <= endMonth)) {
      out.push(`${year}-${String(month).padStart(2, "0")}`);
      month += 1;
      if (month > 12) { month = 1; year += 1; }
    }
    return out;
  }

  // ----------------------------------------------------------------- rendu

  /** État de la collecte, réduit à une pastille.
   *
   * Le détail — angles morts et santé de chaque source — vit dans la section
   * repliée en bas de page : l'information reste accessible sans occuper
   * l'écran d'accueil, dont le sujet est les incidents.
   *
   * Le texte/statut normal de la pastille est rendu une seule fois par
   * `dashboard-audit.js` (`patchRunLabels`) : le dupliquer ici provoquait un
   * flash visible au chargement (deux rendus successifs se remplaçant l'un
   * l'autre). Cette fonction ne garde que ce que `dashboard-audit.js` ne
   * couvre pas : les deux états où aucune donnée de run n'existe encore, et
   * la case à cocher des angles morts. */
  function renderRunPill() {
    const data = state.status;
    const pill = $("#run-pill");
    const text = $("#run-pill-text");

    if (data && data.initialized === false) {
      pill.dataset.status = "";
      text.textContent = "Base non initialisée";
      return;
    }

    if (!data || !data.run.id) {
      pill.dataset.status = "";
      text.textContent = "Aucune collecte";
      return;
    }

    const spots = data.blind_spots || [];
    const box = $("#blindspots");
    if (!spots.length) {
      box.hidden = true;
    } else {
      box.hidden = false;
      $("#blindspots-list").innerHTML = spots.map((spot) => `
        <li><strong>${esc(spot.id)}</strong> — ${esc(spot.status)} ${spot.coverage}%
        ${spot.detail ? `(${esc(spot.detail)})` : ""} : ${esc(spot.reason)}</li>
      `).join("");
    }
  }

  function renderGeneral() {
    if (state.status && state.status.initialized === false) {
      $("#kpi-incidents").textContent = "—";
      $("#kpi-incidents-note").textContent = state.status.message || "Aucune collecte validée disponible.";
      $("#table-count").textContent = "Base non initialisée";
      $("#incidents-table tbody").innerHTML = "<tr><td colspan=\"6\">Aucune collecte validée disponible.</td></tr>";
      ["#chart-month", "#chart-location", "#chart-sector", "#chart-threat"].forEach((id) => {
        const chart = $(id);
        if (chart) chart.textContent = "";
      });
      return;
    }
    const rows = applyFilters(state.incidents);
const quickButtons = [
  ["#f-ocean-indien", "Voir l’Océan Indien"],
  ["#f-auto", "Concessions automobiles"],
  ["#f-grande-distrib", "Grande distribution"],
  ["#f-local", "Local"],
];
    quickButtons.forEach(([id, label]) => {
      const button = $(id);
      if (button) button.textContent = button.getAttribute("aria-pressed") === "true" ? `${label} · ${rows.length}` : label;
    });

    $("#kpi-incidents").textContent = rows.length;
    $("#kpi-incidents-note").textContent = rows.length === state.incidents.length
      ? "événements uniques dans la base"
      : "événements correspondant au filtre actif";

    const months = monthsRange(rows);
    const perMonth = new Map();
    rows.forEach((r) => {
      const key = monthKey(r.date);
      perMonth.set(key, (perMonth.get(key) || 0) + 1);
    });
    barChartTime($("#chart-month"), months.map((m) => ({ label: m, value: perMonth.get(m) || 0 })));

    barChartH($("#chart-location"), countBy(rows, "location"));
    barChartH($("#chart-sector"), countBy(rows, "sector", { dropUnknown: true }));
    barChartH($("#chart-threat"), countBy(rows, "threat"));
    $("#sector-note").textContent = knownNote(rows, "sector", "secteur");

    // Le tableau des incidents (tri, pagination, compteur) est rendu une
    // seule fois par `dashboard-audit.js` (`renderIncidentTable`) : le
    // dupliquer ici provoquait un flash visible au chargement.
  }

  function render() {
    renderRunPill();
    renderGeneral();
  }

  // ----------------------------------------------------------- interactions

  function setupFilters() {
    ["#f-ocean-indien", "#f-auto", "#f-grande-distrib", "#f-local"].forEach((id) => $(id)?.addEventListener("click", (event) => {
      const button = event.currentTarget;
      button.setAttribute("aria-pressed", String(button.getAttribute("aria-pressed") !== "true"));
      document.dispatchEvent(new Event("cyberwatch:filters-changed"));
      render();
    }));
    $("#f-source")?.addEventListener("change", () => {
      document.dispatchEvent(new Event("cyberwatch:filters-changed"));
      render();
    });
  }

  // Le tri lui-même (lecture d'`aria-sort`, re-rendu du tableau) vit dans
  // `dashboard-audit.js` : cette fonction ne fait que gérer le clic —
  // basculer les attributs `aria-sort` — et prévenir le rendu unique via
  // le même événement que les filtres rapides.
  function setupSorting() {
    $$("#incidents-table th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        state.sort = {
          key,
          dir: state.sort.key === key ? -state.sort.dir : (key === "date" ? -1 : 1),
        };
        $$("#incidents-table th[data-sort]").forEach((other) => {
          other.setAttribute("aria-sort", other === th
            ? (state.sort.dir === 1 ? "ascending" : "descending") : "none");
        });
        document.dispatchEvent(new Event("cyberwatch:filters-changed"));
      });
    });
  }

  function setupTheme() {
    const stored = localStorage.getItem("cyberwatch-theme");
    if (stored) document.documentElement.dataset.theme = stored;
    $("#theme-toggle").addEventListener("click", () => {
      const isDark = document.documentElement.dataset.theme === "dark"
        || (!document.documentElement.dataset.theme
            && window.matchMedia("(prefers-color-scheme: dark)").matches);
      const next = isDark ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("cyberwatch-theme", next);
      render();
    });
  }

  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(render, 200);
  });

  // ------------------------------------------------------------ démarrage

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

  async function start() {
    const [incidents, statusData] = await Promise.all([
      load("assets/data/incidents.json", []),
      load("assets/data/status.json", null),
    ]);
    state.incidents = Array.isArray(incidents) ? incidents : [];
    state.status = statusData;

    setupTheme();
    setupFilters();
    setupSorting();
    render();
  }

  document.addEventListener("DOMContentLoaded", start);
})();
