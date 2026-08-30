/* Cyberwatch — garde-fous d’intégrité de publication.
 *
 * Ce module ne transforme jamais un signal CANDIDATE en incident. Il rend
 * visibles deux écarts qui seraient sinon trompeurs pour le lecteur :
 * - un corpus principal dont la fenêtre réellement collectée est plus courte
 *   que les libellés « 30 jours » ;
 * - une veille régionale plus fraîche que le corpus canonique publié.
 */
(() => {
  "use strict";

  const DAY = 864e5;
  const WINDOW_DAYS = 30;
  const STATUS_PATH = "assets/data/status.json";
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

  function formatDay(value) {
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime())
      ? "—"
      : new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric" }).format(date);
  }

  function formatDateTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? "—"
      : new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
  }

  function coverage(status) {
    const run = status?.run || {};
    const start = isoDay(run.target_start);
    const end = isoDay(run.target_end || run.as_of);
    if (!start || !end || end < start) return null;
    return {
      start,
      end,
      days: Math.floor((end - start) / DAY) + 1,
    };
  }

  function showPartialCoverage(status) {
    const span = coverage(status);
    if (!span || span.days >= WINDOW_DAYS) return;

    const alert = document.querySelector("#data-alert");
    const detail = document.querySelector("#data-alert-detail");
    const title = document.querySelector("#veille-title");
    if (alert) {
      const strong = alert.querySelector("strong");
      if (strong) strong.textContent = "Couverture partielle.";
      if (detail) {
        detail.textContent = `Le corpus principal publié couvre ${formatDay(span.start)} au ${formatDay(span.end)} (${span.days} jour${span.days > 1 ? "s" : ""}), pas 30 jours complets.`;
      }
      alert.hidden = false;
    }
    if (title) title.textContent = "Derniers incidents — couverture partielle";
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
    const [statusResult, regionalResult] = await Promise.allSettled([
      loadJson(STATUS_PATH),
      loadJson(REGIONAL_PATH),
    ]);

    if (statusResult.status === "fulfilled") showPartialCoverage(statusResult.value);
    if (regionalResult.status === "fulfilled") {
      waitAndApplyRegional(regionalSummary(regionalResult.value));
    }
  }

  init().catch((error) => console.error("Cyberwatch: contrôle d’intégrité indisponible", error));
})();
