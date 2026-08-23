/* Cyberwatch — utilitaires partagés par le dashboard, sans dépendance externe.
   Ce fichier existe parce que `app.js`, `p2.js` et `p3.js` réécrivaient chacun
   les mêmes sept fonctions, avec des divergences qui finissaient par se voir à
   l'écran (deux noms pour une même source, deux formats de date). */
(() => {
  "use strict";

  const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ESCAPES[char]);
  }

  function normalize(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase("fr-FR")
      .replace(/\s+/g, " ")
      .trim();
  }

  function safeUrl(value) {
    if (!value) return "";
    try {
      const url = new URL(String(value), location.href);
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) {
      return "";
    }
  }

  function host(value) {
    try {
      return new URL(value).hostname.replace(/^www\./, "");
    } catch (_) {
      return "lien";
    }
  }

  function parseDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value) {
    const date = parseDate(value);
    if (!date) return value ? String(value).slice(0, 10) : "—";
    return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" }).format(date);
  }

  function formatDateTime(value) {
    const date = parseDate(value);
    if (!date) return "—";
    return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function formatNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString("fr-FR") : String(value ?? "");
  }

  function plural(count, singular, pluralForm) {
    return Number(count) > 1 ? (pluralForm || `${singular}s`) : singular;
  }

  /* Libellés de sources : la table vient de `status.json`, produite par
     `config.SOURCE_LABELS`. Tant qu'elle n'est pas chargée, l'identifiant brut
     fait office de repli — visible, donc corrigible, plutôt que silencieux. */
  let sourceLabels = {};

  function setSourceLabels(labels) {
    sourceLabels = labels && typeof labels === "object" ? labels : {};
  }

  function sourceLabel(id) {
    const key = String(id || "");
    return sourceLabels[key] || key || "Source";
  }

  function initialAccessLabel(value) {
    return ({ phishing: "Phishing", compromised_credentials: "Identifiants compromis", vulnerability_exploitation: "Exploitation d’une vulnérabilité", remote_access: "Accès distant", third_party: "Tiers compromis", malware: "Malware", other: "Autre" })[value] || "";
  }

  /* §Transparence : une source en échec ne doit jamais devenir un faux succès.
     `load` remonte l'issue au lieu de l'absorber dans une valeur de repli. */
  async function load(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-cache" });
      if (!response.ok) throw new Error(String(response.status));
      return { ok: true, data: await response.json() };
    } catch (error) {
      console.error(`Données indisponibles : ${path}`, error);
      return { ok: false, data: fallback };
    }
  }

  function reportDataFailure(label) {
    const box = document.getElementById("data-alert");
    const detail = document.getElementById("data-alert-detail");
    if (!box || !detail) return;
    const known = detail.textContent ? detail.textContent.split(" · ") : [];
    if (!known.includes(label)) known.push(label);
    detail.textContent = known.join(" · ");
    box.hidden = false;
  }

  function countBy(rows, key, { dropUnknown = false } = {}) {
    const counts = new Map();
    rows.forEach((row) => {
      const value = row[key] || "Inconnu";
      if (dropUnknown && normalize(value) === "inconnu") return;
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    return Array.from(counts, ([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label, "fr"));
  }

  /* Index de recherche construit une fois.
     La version précédente sérialisait tous les faits d'un incident à chaque
     frappe : « item_id » renvoyait 860 résultats sur 871, et chaque touche
     coûtait 21 ms. On n'indexe donc que des champs porteurs de sens pour un
     lecteur, jamais la structure interne des enregistrements. */
  const INDEXED_FACT_FIELDS = ["threat_actor", "third_party", "fine_location", "impact", "summary"];

  function searchableText(incident) {
    const parts = [
      incident.org, incident.sector, incident.threat, incident.location, incident.summary,
      ...(incident.sources || []).map(sourceLabel),
      ...(incident.urls || []).map((url) => host(safeUrl(url))),
      incident.local && incident.local.summary,
    ];
    (incident.facts || []).forEach((fact) => {
      INDEXED_FACT_FIELDS.forEach((field) => parts.push(fact[field]));
    });
    return normalize(parts.filter(Boolean).join(" "));
  }

  function buildSearchIndex(rows) {
    const index = new Map();
    rows.forEach((row) => index.set(row, searchableText(row)));
    return index;
  }

  window.CW = {
    esc, normalize, safeUrl, host,
    parseDate, formatDate, formatDateTime, formatNumber, plural,
    setSourceLabels, sourceLabel, initialAccessLabel,
    load, reportDataFailure,
    countBy, searchableText, buildSearchIndex,
  };
})();
