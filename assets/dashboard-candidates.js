/* Affichage léger des signaux CANDIDATE de la veille régionale. */
(() => {
  "use strict";

  const SNAPSHOT_URL = "sources/veillellm/cyberattaques_reunion_mayotte_2026.json";

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  const safeUrl = (value) => {
    try {
      const url = new URL(value, window.location.href);
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) {
      return "";
    }
  };

  const formatDate = (value) => {
    const date = value ? new Date(`${value}T00:00:00`) : null;
    return date && !Number.isNaN(date.getTime())
      ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric" }).format(date)
      : "—";
  };

  function sourceLinks(record) {
    return (record.sources || [])
      .map((value, index) => {
        const url = safeUrl(value);
        return url
          ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">Source ${index + 1}</a>`
          : "";
      })
      .filter(Boolean)
      .join("");
  }

  function card(record) {
    const threat = record.type_menace && record.type_menace !== "Inconnu"
      ? `<span>${esc(record.type_menace)}</span>`
      : "";
    const sector = record.secteur && record.secteur !== "Inconnu"
      ? `<span>${esc(record.secteur)}</span>`
      : "";
    const reason = String(record.admission_reason || "Signal à vérifier.").trim();
    const summary = String(record.synthese || record.statut || "").trim();
    const score = Number.isFinite(Number(record.score_cyberattaque))
      ? `<small>Confiance cyber : ${esc(record.score_cyberattaque)}/100</small>`
      : "";

    return `<article class="incident-card candidate-signal">
      <div class="incident-main">
        <div class="incident-card-top"><time datetime="${esc(record.date || "")}">${esc(formatDate(record.date))}</time>${record.territoire ? `<span>${esc(record.territoire)}</span>` : ""}</div>
        <strong class="incident-org-link">${esc(record.organisation || "Organisation inconnue")}</strong>
        <p class="incident-tags"><span data-status="PARTIAL">À confirmer</span>${threat}${sector}</p>
        ${summary ? `<p class="incident-summary-text">${esc(summary)}</p>` : ""}
        <p class="hint"><strong>Pourquoi candidat :</strong> ${esc(reason)}</p>
        ${score}
      </div>
      <div class="incident-side"><div class="incident-source-badges">${sourceLinks(record)}</div></div>
    </article>`;
  }

  async function init() {
    const focusCard = document.querySelector("#focus-card");
    if (!focusCard) return;

    try {
      const response = await fetch(SNAPSHOT_URL, { cache: "no-store" });
      if (!response.ok) return;
      const payload = await response.json();
      const candidates = Array.isArray(payload.records)
        ? payload.records
          .filter((record) => String(record?.admission || "").toUpperCase() === "CANDIDATE")
          .sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")))
        : [];
      if (!candidates.length) return;

      const section = document.createElement("section");
      section.id = "candidate-signals";
      section.className = "card";
      section.setAttribute("aria-labelledby", "candidate-signals-title");
      section.innerHTML = `<div class="card-head"><h2 id="candidate-signals-title">Signaux à confirmer</h2><p class="hint">${candidates.length} signal${candidates.length > 1 ? "aux" : ""} en investigation · hors KPI incidents</p></div><div class="incident-list">${candidates.map(card).join("")}</div>`;
      focusCard.insertAdjacentElement("afterend", section);
    } catch (error) {
      console.warn("Cyberwatch: signaux CANDIDATE indisponibles", error);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
