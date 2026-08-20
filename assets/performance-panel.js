/* Audit Performance — extension isolée du dashboard Cyberwatch. */
(() => {
  "use strict";

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[char]));

  function duration(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds)) return "—";
    if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
    const minutes = Math.floor(seconds / 60);
    const rest = Math.round(seconds % 60);
    return `${minutes} min ${String(rest).padStart(2, "0")} s`;
  }

  function number(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed.toLocaleString("fr-FR") : "—";
  }

  function metric(label, value, note = "") {
    return `<article class="kpi"><h2>${esc(label)}</h2><p class="kpi-value">${esc(value)}</p>${note ? `<p class="kpi-note">${esc(note)}</p>` : ""}</article>`;
  }

  function render(performance) {
    const main = document.querySelector("main.wrap");
    const reliability = document.querySelector("#fiabilite");
    if (!main || document.querySelector("#performance")) return;

    const latest = performance?.latest || {};
    const history = Array.isArray(performance?.history) ? performance.history.slice().reverse() : [];
    const section = document.createElement("section");
    section.className = "card reliability";
    section.id = "performance";
    section.setAttribute("aria-labelledby", "performance-title");

    if (!latest.run_id) {
      section.innerHTML = '<h2 id="performance-title">Performance</h2><p class="muted">Aucune mesure de performance instrumentée disponible.</p>';
    } else {
      const changed = Number(latest.snapshot_items_modified || 0);
      const unchanged = Number(latest.snapshot_items_unchanged || 0);
      const totalCompared = changed + unchanged;
      const cacheTotal = Number(latest.french_detail_cache_hits || 0) + Number(latest.french_detail_network_fetches || 0);
      const cacheRate = cacheTotal ? Math.round(100 * Number(latest.french_detail_cache_hits || 0) / cacheTotal) : 0;
      section.innerHTML = `
        <div class="card-head">
          <div><h2 id="performance-title">Performance</h2><p class="muted">Dernier run instrumenté · ${esc(latest.mode || "—")}</p></div>
        </div>
        <div class="kpis kpis-overview">
          ${metric("Durée totale", duration(latest.duration_s), latest.run_id || "")}
          ${metric("Qualification", duration(latest.qualify_duration_s), "qualify() canonique")}
          ${metric("SourceFacts réutilisés", number(latest.sourcefacts_reused), `${number(latest.sourcefacts_llm_calls)} appel(s) LLM`)}
          ${metric("SourceFacts LLM", duration(latest.sourcefacts_llm_duration_s), "temps réseau / modèle")}
          ${metric("Cache FrenchBreaches", `${cacheRate} %`, `${number(latest.french_detail_cache_hits)} cache · ${number(latest.french_detail_network_fetches)} réseau`)}
          ${metric("Delta snapshot", `${number(latest.items_new)} nouveau(x)`, totalCompared ? `${number(changed)} modifié(s) · ${number(unchanged)} inchangé(s)` : "aucun item comparable")}
        </div>
        <details class="sources-detail">
          <summary>Historique des performances</summary>
          <div class="table-scroll">
            <table class="data-table" id="performance-history-table">
              <thead><tr><th>Run</th><th>Mode</th><th>Durée</th><th>Qualification</th><th>Nouveaux</th><th>Modifiés</th><th>SourceFacts cache</th><th>LLM</th><th>FrenchBreaches cache / réseau</th></tr></thead>
              <tbody>${history.slice(0, 10).map((row) => `<tr>
                <td data-label="Run">${esc(row.run_id || "—")}</td>
                <td data-label="Mode">${esc(row.mode || "—")}</td>
                <td data-label="Durée">${esc(duration(row.duration_s))}</td>
                <td data-label="Qualification">${esc(duration(row.qualify_duration_s))}</td>
                <td data-label="Nouveaux" class="num">${esc(number(row.items_new))}</td>
                <td data-label="Modifiés" class="num">${esc(number(row.snapshot_items_modified))}</td>
                <td data-label="SourceFacts cache" class="num">${esc(number(row.sourcefacts_reused))}</td>
                <td data-label="LLM" class="num">${esc(number(row.sourcefacts_llm_calls))} · ${esc(duration(row.sourcefacts_llm_duration_s))}</td>
                <td data-label="FrenchBreaches" class="num">${esc(number(row.french_detail_cache_hits))} / ${esc(number(row.french_detail_network_fetches))}</td>
              </tr>`).join("")}</tbody>
            </table>
          </div>
        </details>`;
    }

    if (reliability?.parentNode === main) reliability.insertAdjacentElement("afterend", section);
    else main.appendChild(section);
  }

  document.addEventListener("DOMContentLoaded", async () => {
    try {
      const response = await fetch("assets/data/status.json", { cache: "no-cache" });
      if (!response.ok) return;
      const status = await response.json();
      render(status?.performance || null);
    } catch (_) {
      // Le dashboard principal reste fonctionnel si la télémétrie est absente.
    }
  });
})();
