/* Cyberwatch — ajustements de placement des contrôles du dashboard. */
(() => {
  "use strict";

  function placeIncidentDetailButtons() {
    document.querySelectorAll("#incidents-table tbody tr:not(.incident-details-row)").forEach((row) => {
      const button = row.querySelector(".incident-details-toggle");
      const sourceCell = row.querySelector('td[data-label="Sources"]');
      if (!button || !sourceCell || button.parentElement === sourceCell) return;
      sourceCell.appendChild(button);
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const body = document.querySelector("#incidents-table tbody");
    if (!body) return;

    placeIncidentDetailButtons();
    new MutationObserver(placeIncidentDetailButtons).observe(body, {
      childList: true,
      subtree: true,
    });
  });
})();
