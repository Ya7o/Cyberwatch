/* Signaler uniquement un décalage réel de la veille régionale avec le corpus. */
(() => {
  "use strict";
  const REGIONAL_PATH = "sources/veillellm/cyberattaques_reunion_mayotte_2026.json";
  let snapshot = null;
  let latest = null;
  let scope = "all";
  const DAY = 864e5;
  const key = (org, date) => `${String(org || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()}|${date}`;

  function applyRegionalSummary() {
    const note = document.querySelector("#regional-watch-status");
    if (!note || !snapshot || !latest) return;
    note.hidden = true;
    note.textContent = "";
    if (!["focus", "ocean"].includes(scope)) return;
    const end = new Date(String(snapshot.metadata?.generated_at || "").slice(0, 10));
    if (Number.isNaN(end.getTime())) return;
    const start = new Date(end.getTime() - 29 * DAY);
    const published = new Set(latest.map((row) => key(row.org, row.date)));
    const pending = (snapshot.records || []).filter((row) => {
      const date = new Date(row.date);
      return ["ACCEPTED", "CANDIDATE"].includes(row.admission) && date >= start && date <= end && !published.has(key(row.organisation, row.date));
    }).length;
    if (!pending) return;
    note.hidden = false;
    note.textContent = `${pending} publication${pending > 1 ? "s" : ""} régionale${pending > 1 ? "s" : ""} en attente de synchronisation.`;
  }

  document.addEventListener("cyberwatch:render", (event) => { scope = event.detail?.scope || "all"; applyRegionalSummary(); });
  Promise.all([REGIONAL_PATH, "assets/data/latest.json"].map(async (path) => {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`${path}: ${response.status}`);
    return response.json();
  })).then(([regional, rows]) => { snapshot = regional; latest = Array.isArray(rows) ? rows : []; applyRegionalSummary(); })
    .catch((error) => console.error("Cyberwatch : veille régionale indisponible", error));
})();
