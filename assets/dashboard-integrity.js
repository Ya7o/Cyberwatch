/* Cyberwatch — garde-fou de veille régionale.
 *
 * La couverture temporelle et la fraîcheur sont désormais portées par le
 * contrat status.json et rendues par dashboard-v2.js. Ce module ne transforme
 * jamais un signal CANDIDATE en incident ; il rend seulement visible une veille
 * régionale plus fraîche que le corpus canonique publié.
 */
(() => {
  "use strict";

  const DAY = 864e5;
  const WINDOW_DAYS = 30;
  const REGIONAL_PATH = "sources/veillellm/cyberattaques_reunion_mayotte_2026.json";
  const FOCUS = new Set(["La Réunion", "Mayotte"]);

  async function loadJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`${path}: ${response.status}`);
    return response.json();
  }

  function isoDay(value) {
    const text = String(value || "").slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return null;
    const date = new Date(`${text}T00:00:00Z`);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDateTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? "—"
      : new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
  }

  function regionalSummary(snapshot) {
    const metadata = snapshot?.metadata || {};
    const asOf = isoDay(metadata.generated_at);
    const records = Array.isArray(snapshot?.records) ? snapshot.records : [];
    if (!asOf) return null;

    const cutoff = new Date(asOf.getTime() - (WINDOW_DAYS - 1) * DAY);
    const recent = records.filter((row) => {
      if (!row || !FOCUS.has(String(row.territoire || ""))) return false;
      const day = isoDay(row.date);
      return day && day >= cutoff && day <= asOf;
    });

    return {
      generatedAt: String(metadata.generated_at || ""),
      accepted: recent.filter((row) => String(row.admission || "").toUpperCase() === "ACCEPTED").length,
      candidates: recent.filter((row) => String(row.admission || "").toUpperCase() === "CANDIDATE").length,
    };
  }

  function plural(value, singular, pluralForm = `${singular}s`) {
    return `${value} ${value > 1 ? pluralForm : singular}`;
  }

  function applyRegionalSummary(summary) {
    const body = document.querySelector("#focus-body");
    if (!body || !summary) return false;

    const cards = body.querySelectorAll(".incident-card");
    const bubble = body.querySelector(".status-bubble");
    if (!cards.length && !bubble) return false;

    const stamp = summary.generatedAt ? ` Dernière veille locale : ${formatDateTime(summary.generatedAt)}.` : "";
    if (cards.length) {
      const note = document.createElement("p");
      note.className = "hint regional-watch-note";
      note.dataset.regionalWatch = "true";
      note.textContent = summary.candidates
        ? `${plural(summary.candidates, "signal non confirmé")} également en veille sur 30 jours.${stamp}`
        : `Aucun signal régional non confirmé supplémentaire sur 30 jours.${stamp}`;
      body.appendChild(note);
      return true;
    }

    if (summary.accepted > 0) {
      bubble.classList.remove("status-bubble--quiet");
      bubble.classList.add("status-bubble--active");
      bubble.textContent = `${plural(summary.accepted, "incident cyber retenu", "incidents cyber retenus")} par la veille locale sur les 30 derniers jours, mais pas encore synchronisé${summary.accepted > 1 ? "s" : ""} dans le corpus principal.${summary.candidates ? ` ${plural(summary.candidates, "signal non confirmé")} en veille.` : ""}${stamp}`;
      return true;
    }

    bubble.textContent = `Aucun incident cyber retenu à La Réunion / Mayotte sur les 30 derniers jours.${summary.candidates ? ` ${plural(summary.candidates, "signal non confirmé")} en veille.` : ""}${stamp}`;
    return true;
  }

  function waitAndApplyRegional(summary, attempts = 60) {
    if (applyRegionalSummary(summary) || attempts <= 0) return;
    window.setTimeout(() => waitAndApplyRegional(summary, attempts - 1), 100);
  }

  async function init() {
    const snapshot = await loadJson(REGIONAL_PATH);
    waitAndApplyRegional(regionalSummary(snapshot));
  }

  init().catch((error) => console.error("Cyberwatch: contrôle d’intégrité indisponible", error));
})();
