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

  //: Libellés courts des niveaux de run, pour la pastille.
  const LABELS = { HEALTHY: "complète", DEGRADED: "partielle", BROKEN: "incomplète" };

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

  function applyFilters(incidents) {
    return incidents.filter((incident) => {
      const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
      const oceanLocations = new Set(["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"]);
      if (ocean && !oceanLocations.has(incident.location)) return false;
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
   * l'écran d'accueil, dont le sujet est les incidents. */
  function renderRunPill() {
    const data = state.status;
    const pill = $("#run-pill");
    const text = $("#run-pill-text");

    if (!data || !data.run.id) {
      pill.dataset.status = "";
      text.textContent = "Aucune collecte";
      $("#reliability-summary").textContent =
        "La première collecte automatique n'a pas encore eu lieu.";
      return;
    }

    const run = data.run;
    const c = data.counts;
    pill.dataset.status = run.overall;
    text.textContent = `Collecte ${LABELS[run.overall] || run.overall} · ${run.health}/100`;
    pill.title = (data.labels.run_status && data.labels.run_status[run.overall]) || "";

    $("#kpi-date").textContent = formatDate(run.as_of);
    $("#kpi-new").textContent =
      `+${run.new_incidents} incident${run.new_incidents > 1 ? "s" : ""} au dernier run`;
    $("#foot-method").textContent = data.method_id || "—";
    $("#foot-hash").textContent = (run.incidents_hash || "—").slice(0, 16);

    const spots = data.blind_spots || [];
    $("#reliability-summary").textContent =
      `${c.ok} source${c.ok > 1 ? "s" : ""} complète${c.ok > 1 ? "s" : ""}, `
      + `${c.partial} partielle${c.partial > 1 ? "s" : ""}, ${c.fail} en échec`
      + (spots.length ? ` · ${spots.length} angle${spots.length > 1 ? "s" : ""} mort${spots.length > 1 ? "s" : ""}` : "");

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
    const rows = applyFilters(state.incidents);
    const oceanButton = $("#f-ocean-indien");
    if (oceanButton?.getAttribute("aria-pressed") === "true") {
      oceanButton.textContent = `Océan Indien · ${rows.length}`;
    } else if (oceanButton) {
      oceanButton.textContent = "Océan Indien";
    }

    $("#kpi-incidents").textContent = rows.length;
    $("#kpi-incidents-note").textContent =
      rows.length === state.incidents.length ? "sur l'ensemble de la base" : "sur la sélection";
    $("#kpi-orgs").textContent = new Set(rows.map((r) => r.org).filter(Boolean)).size;
    $("#kpi-multi").textContent = rows.filter((r) => r.sources.length >= 2).length;

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

    renderIncidentsTable($("#incidents-table tbody"), rows, $("#table-count"));
  }

  function renderIncidentsTable(tbody, rows, counter) {
    const { key, dir } = state.sort;
    const sorted = rows.slice().sort((a, b) => {
      const left = key === "items" ? a.sources.length : a[key] || "";
      const right = key === "items" ? b.sources.length : b[key] || "";
      if (left < right) return -dir;
      if (left > right) return dir;
      return 0;
    });

    const LIMIT = 300;
    const shown = sorted.slice(0, LIMIT);
    if (counter) {
      counter.textContent = sorted.length > LIMIT
        ? `${shown.length} incidents affichés sur ${sorted.length}`
        : `${sorted.length} incident${sorted.length > 1 ? "s" : ""}`;
    }

    tbody.innerHTML = shown.map((incident) => {
      const link = incident.urls[0]
        ? `<a href="${esc(incident.urls[0])}" target="_blank" rel="noopener">${esc(incident.org || "Organisation inconnue")}</a>`
        : esc(incident.org || "Organisation inconnue");
      const basis = incident.basis === "EVENT" ? "date d'événement" : "date de publication";
      return `<tr>
        <td class="num" title="${esc(basis)}">${esc(incident.date || "—")}</td>
        <td class="wrap-cell">${link}</td>
        <td>${esc(incident.location)}</td>
        <td>${esc(incident.sector)}</td>
        <td>${esc(incident.threat)}</td>
        <td class="num" title="${esc(incident.sources.join(", "))}">${incident.sources.length}</td>
      </tr>`;
    }).join("");
  }

  function renderSources() {
    const rows = (state.status && state.status.sources) || [];
    const tbody = $("#sources-table tbody");

    tbody.innerHTML = rows.map((source) => {
      // Un zéro n'est un vrai zéro que si le protocole est allé au bout.
      let itemsCell;
      if (source.status === "SKIPPED") {
        itemsCell = `<span class="zero-untrusted" title="Source hors périmètre de ce run">—</span>`;
      } else if (source.items === 0) {
        itemsCell = source.zero_is_trusted
          ? `<span class="zero-trusted" title="Protocole complet : aucun incident sur la période">0 vérifié</span>`
          : `<span class="zero-untrusted" title="Protocole incomplet : information indisponible">indisponible</span>`;
      } else {
        itemsCell = `<span class="zero-trusted">${source.items}</span>`;
      }

      const detail = source.comment || source.reason || "";
      const access = source.access_method || "—";
      return `<tr>
        <td title="${esc(source.id)} — ${esc(source.url)}">${esc(source.id)}</td>
        <td title="${esc(source.layer)}">${esc(source.layer)}</td>
        <td><span class="chip" data-status="${esc(source.status)}">${esc(source.status)}</span></td>
        <td>
          <div class="coverage">
            <span class="coverage-track"><span class="coverage-fill" style="width:${source.coverage}%"></span></span>
            <span class="coverage-num">${source.coverage}%</span>
          </div>
        </td>
        <td class="num">${itemsCell}</td>
        <td class="cell-clip" title="${esc(access)}">${esc(access)}</td>
        <td class="cell-detail">${esc(detail)}</td>
      </tr>`;
    }).join("");
  }

  function render() {
    renderRunPill();
    renderGeneral();
    renderSources();
  }

  // ----------------------------------------------------------- interactions

  function setupFilters() {
    $("#f-ocean-indien")?.addEventListener("click", (event) => {
      const button = event.currentTarget;
      button.setAttribute("aria-pressed", String(button.getAttribute("aria-pressed") !== "true"));
      document.dispatchEvent(new Event("cyberwatch:filters-changed"));
      render();
    });
  }

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
        render();
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
