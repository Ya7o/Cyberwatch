/* Cyberwatch — évite les synthèses redondantes dans le détail d'un incident. */
(() => {
  "use strict";

  function hasSourceSummary(grid) {
    return Array.from(grid.querySelectorAll(".incident-fact-row")).some((row) => {
      const label = row.querySelector(".incident-fact-label");
      const value = row.querySelector(".incident-fact-value");
      return label && value && label.textContent.trim().replace(/\s+/g, " ") === "Synthèse :" && value.textContent.trim();
    });
  }

  function dedupeIncidentSummaries(root = document) {
    root.querySelectorAll(".incident-details-grid").forEach((grid) => {
      const globalSummary = grid.querySelector(":scope > .incident-summary");
      if (!globalSummary) return;

      /* La synthèse globale est une vue consolidée. Dès qu'une synthèse
         détaillée existe dans une fiche source, afficher les deux crée une
         répétition visuelle et sémantique. On conserve donc les synthèses
         source, plus précises et traçables. */
      if (hasSourceSummary(grid)) globalSummary.remove();
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    dedupeIncidentSummaries();
    const tbody = document.querySelector("#incidents-table tbody");
    if (!tbody) return;
    new MutationObserver(() => dedupeIncidentSummaries(tbody)).observe(tbody, {
      childList: true,
      subtree: true,
    });
  });
})();
