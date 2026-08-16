/* Lecture instantanée de la criticité des données à partir des faits déjà rendus. */
(() => {
  "use strict";

  const SENSITIVE_MARKERS = [
    "sante", "medical", "patient", "diagnostic", "patholog", "ordonnance", "traitement", "vaccin",
    "nir", "securite sociale", "numero de securite sociale",
    "passeport", "carte d identite", "piece d identite", "permis de conduire", "biometr", "selfie",
    "mot de passe", "password", "hash", "token", "otp", "secret", "cle api", "authent",
    "iban", "rib", "bancair", "carte de paiement", "carte bancaire", "releve de compte",
    "revenu", "salaire", "patrimoine",
  ];

  const PERSONAL_EXACT = new Set([
    "nom", "prenom", "nom et prenom", "nom, prenom", "nom / prenom",
  ]);
  const PERSONAL_MARKERS = [
    "e-mail", "email", "telephone", "adresse postale", "date de naissance",
    "numero client", "identifiant client", "coordonnees personnelles",
  ];

  const normalize = (value) => String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("fr-FR");

  function levelForCell(cell) {
    const values = Array.from(cell.querySelectorAll(".incident-data-value"))
      .map((node) => normalize(node.textContent));
    if (values.some((value) => SENSITIVE_MARKERS.some((marker) => value.includes(marker)))) {
      return ["sensitive", "Données sensibles"];
    }
    if (values.some((value) =>
    PERSONAL_EXACT.has(value.trim()) || PERSONAL_MARKERS.some((marker) => value.includes(marker))
  )) return ["personal", "Données personnelles"];
    if (values.length) return ["unknown", "Données non qualifiées"];

    const factsText = normalize(cell.querySelector(".incident-facts")?.textContent || "");
    if (/donnees touchees|volume|fichiers/.test(factsText)) {
      return ["unknown", "Données non qualifiées"];
    }
    return null;
  }

  function patch() {
    document.querySelectorAll("#incidents-table .org-cell").forEach((cell) => {
      cell.querySelector(":scope > .data-sensitivity")?.remove();
      const level = levelForCell(cell);
      if (!level) return;
      const [kind, label] = level;
      const badge = document.createElement("span");
      badge.className = `data-sensitivity data-sensitivity--${kind}`;
      badge.textContent = label;
      badge.title = kind === "unknown"
        ? "Des mesures de fuite sont disponibles mais la nature des données n'est pas qualifiée."
        : "Criticité calculée déterministement à partir des types de données publiés par la source.";
      const details = cell.querySelector(":scope > .incident-facts, :scope > .local-analysis");
      if (details) cell.insertBefore(badge, details);
      else cell.appendChild(badge);
    });
  }

  function installCss() {
    const style = document.createElement("style");
    style.textContent = `
      .data-sensitivity{display:inline-flex;align-items:center;margin:0 0 0 7px;padding:2px 7px;border-radius:999px;border:1px solid var(--border);font-size:11px;font-weight:650;vertical-align:middle}
      .data-sensitivity--unknown{background:color-mix(in srgb,var(--text-muted) 12%,transparent);color:var(--text-secondary)}
      .data-sensitivity--personal{background:rgba(217,154,0,.14);border-color:rgba(217,154,0,.38);color:var(--text-primary)}
      .data-sensitivity--sensitive{background:rgba(214,69,69,.14);border-color:rgba(214,69,69,.42);color:var(--text-primary)}
    `;
    document.head.appendChild(style);
  }

  document.addEventListener("DOMContentLoaded", () => {
    installCss();
    const table = document.querySelector("#incidents-table tbody");
    if (!table) return;
    const observer = new MutationObserver(() => requestAnimationFrame(patch));
    observer.observe(table, { childList: true, subtree: true });
    patch();
  });
})();
