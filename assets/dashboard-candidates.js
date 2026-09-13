/* Badge discret pour les incidents Veille LLM encore CANDIDATE. */
(() => {
  "use strict";

  const CANDIDATE = "CANDIDATE";
  const DATA_PATHS = ["assets/data/latest.json", "assets/data/incidents.json"];
  const candidates = new Map();
  let activeIncidentId = "";

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  async function loadRows(path) {
    try {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) return [];
      const rows = await response.json();
      return Array.isArray(rows) ? rows : [];
    } catch (_) {
      return [];
    }
  }

  function badge(reason) {
    const title = reason ? ` title="${esc(reason)}"` : "";
    return `<span data-candidate-badge data-status="PARTIAL"${title}>À confirmer</span>`;
  }

  function decorateCard(card) {
    const id = String(card?.dataset?.id || "");
    const candidate = candidates.get(id);
    if (!candidate || card.querySelector("[data-candidate-badge]")) return;

    let tags = card.querySelector(".incident-tags");
    if (!tags) {
      tags = document.createElement("p");
      tags.className = "incident-tags";
      const org = card.querySelector(".incident-org-link");
      if (org) org.insertAdjacentElement("afterend", tags);
      else card.querySelector(".incident-main")?.prepend(tags);
    }
    tags.insertAdjacentHTML("afterbegin", badge(candidate.admission_reason || ""));
  }

  function decorateCards(root = document) {
    root.querySelectorAll?.(".incident-card[data-id]").forEach(decorateCard);
  }

  function decorateDetail() {
    const content = document.querySelector("#detail-dialog-content");
    if (!content) return;
    const existing = content.querySelector("[data-candidate-note]");
    const candidate = candidates.get(activeIncidentId);
    if (!candidate) {
      existing?.remove();
      return;
    }
    if (existing?.dataset?.candidateNote === activeIncidentId) return;
    existing?.remove();

    const note = document.createElement("p");
    note.className = "hint";
    note.dataset.candidateNote = activeIncidentId;
    const reason = String(candidate.admission_reason || "Signal en cours de vérification.").trim();
    note.innerHTML = `<strong>À confirmer.</strong> ${esc(reason)}`;
    const heading = content.querySelector("h2, h3");
    if (heading) heading.insertAdjacentElement("afterend", note);
    else content.prepend(note);
  }

  async function init() {
    const groups = await Promise.all(DATA_PATHS.map(loadRows));
    for (const row of groups.flat()) {
      if (String(row?.admission || "").toUpperCase() !== CANDIDATE || !row?.id) continue;
      candidates.set(String(row.id), row);
    }
    if (!candidates.size) return;

    decorateCards();
    document.addEventListener("click", (event) => {
      const trigger = event.target.closest?.("[data-open-id]");
      if (!trigger) return;
      activeIncidentId = String(trigger.dataset.openId || "");
      queueMicrotask(decorateDetail);
    }, true);

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof Element)) return;
          if (node.matches?.(".incident-card[data-id]")) decorateCard(node);
          decorateCards(node);
        });
      }
      decorateDetail();
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
