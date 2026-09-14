/* Cyberwatch — filet de secours UI.
 *
 * Objectif : éviter un écran vide si le dashboard principal casse avant le
 * rendu, par exemple sur une exception de stockage navigateur, de cache ou de
 * module annexe. Ce fichier ne remplace pas dashboard-v2.js : il ne s'active
 * que si les listes restent vides alors que latest.json contient des données.
 */
(() => {
  "use strict";

  const CHECK_DELAY_MS = 1400;
  const DATA_PATH = "assets/data/latest.json";
  const STATUS_PATH = "assets/data/status.json";
  const FOCUS_FALLBACK = ["La Réunion", "Mayotte"];
  const SOURCE_LABELS = {
    RANSOMWARE_LIVE: "Ransomware.live",
    CYBERATTAQUE_ORG: "Cyberattaque.org",
    FRENCHBREACHES: "FrenchBreaches",
    BONJOURLAFUITE: "BonjourLaFuite",
    VEILLE_LLM: "Veille locale Réunion / Mayotte",
  };

  let scheduled = false;
  let rendered = false;
  let lastFailure = "rendu principal absent";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const esc = (value) => String(value ?? "").replace(/[&<>\"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[char]);
  const known = (value) => Boolean(String(value ?? "").trim()) && String(value).trim() !== "Inconnu";
  const sourceLabel = (id) => SOURCE_LABELS[id] || id || "Source";
  const formatNumber = (value) => new Intl.NumberFormat("fr-FR").format(Number(value || 0));
  const formatDate = (value) => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime())
      ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric" }).format(date)
      : "—";
  };
  const formatDateTime = (value) => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime())
      ? new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date)
      : "—";
  };
  const safeUrl = (value) => {
    try {
      const url = new URL(value);
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) {
      return "";
    }
  };

  async function loadJson(path, fallback) {
    try {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) throw new Error(`${path}: ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error(`Cyberwatch failsafe: échec de chargement ${path}`, error);
      return fallback;
    }
  }

  function dashboardAlreadyRendered() {
    return Boolean($("#veille-list .incident-card") || $("#focus-body .incident-card") || $("#s-list .incident-card"));
  }

  function dashboardNeedsFallback() {
    // Le texte d'un module annexe ou un état vide rendu après un fetch échoué
    // ne prouve pas que le runtime principal fonctionne. La seule preuve
    // fiable est la présence d'au moins une carte ; latest.json tranche ensuite
    // entre une base réellement vide et un rendu défaillant.
    return Boolean($("#veille-list")) && !dashboardAlreadyRendered();
  }

  function sourceBadges(row) {
    const direct = new Map((row.source_links || []).map((link) => [link.source, safeUrl(link.url)]));
    return Array.from(new Set(row.sources || [])).map((id) => {
      const url = direct.get(id);
      return url
        ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(sourceLabel(id))}</a>`
        : `<span>${esc(sourceLabel(id))}</span>`;
    }).join("");
  }

  function cardHtml(row) {
    const tags = [row.threat, row.sector].filter(known).map((value) => `<span>${esc(value)}</span>`).join("");
    const summary = String(row.summary || "").replace(/\s+/g, " ").trim();
    return `<article class="incident-card" data-id="${esc(row.id)}">
      <div class="incident-main">
        <div class="incident-card-top"><time datetime="${esc(row.date)}">${esc(formatDate(row.date))}</time>${known(row.location) ? `<span>${esc(row.location)}</span>` : ""}</div>
        <strong class="incident-org-link">${esc(row.org || "Organisation inconnue")}</strong>
        ${tags ? `<p class="incident-tags">${tags}</p>` : ""}
        ${summary ? `<p class="incident-summary-text">${esc(summary)}</p>` : ""}
      </div>
      <div class="incident-side"><div class="incident-source-badges">${sourceBadges(row)}</div></div>
    </article>`;
  }

  function activateVeilleView() {
    $$(".views [data-view]").forEach((button) => button.setAttribute("aria-current", String(button.dataset.view === "veille")));
    $$(".view").forEach((view) => { view.hidden = view.id !== "view-veille"; });
  }

  function renderAlert(detail) {
    const alert = $("#data-alert");
    const text = $("#data-alert-detail");
    const strong = alert?.querySelector("strong");
    if (!alert || !text || !strong) return;
    alert.hidden = false;
    alert.dataset.status = "warning";
    strong.textContent = "Mode de secours du dashboard.";
    text.textContent = detail;
  }

  function renderHeader(status) {
    const pill = $("#run-pill");
    const text = $("#run-pill-text");
    if (!pill || !text) return;
    const sources = status?.sources || [];
    const ok = sources.filter((source) => String(source.status || "").toUpperCase() === "OK").length;
    const total = sources.length || 0;
    const stamp = formatDateTime(status?.run?.as_of);
    text.textContent = total ? `${ok}/${total} sources · snapshot ${stamp}` : "Snapshot chargé en secours";
    pill.dataset.status = "degraded";
  }

  async function renderFailsafe() {
    scheduled = false;
    if (rendered || !dashboardNeedsFallback()) return;

    const [latest, status] = await Promise.all([
      loadJson(DATA_PATH, []),
      loadJson(STATUS_PATH, null),
    ]);
    if (!Array.isArray(latest) || !latest.length || dashboardAlreadyRendered()) return;

    rendered = true;
    const focusLocations = Array.isArray(status?.focus_locations) && status.focus_locations.length
      ? status.focus_locations
      : FOCUS_FALLBACK;
    const local = latest.filter((row) => focusLocations.includes(row.location));

    activateVeilleView();
    renderHeader(status);
    renderAlert(`Le rendu principal ne s'est pas terminé (${lastFailure}). Les données publiées existent ; affichage minimal chargé depuis ${DATA_PATH}.`);

    const focusBody = $("#focus-body");
    if (focusBody) {
      focusBody.innerHTML = local.length
        ? `<p class="status-bubble status-bubble--active"><strong>${local.length}</strong> incident${local.length > 1 ? "s" : ""} à La Réunion / Mayotte sur les 30 derniers jours.</p><div class="focus-list">${local.map(cardHtml).join("")}</div>`
        : '<p class="status-bubble status-bubble--quiet">Aucun incident à La Réunion / Mayotte sur les 30 derniers jours.</p>';
    }

    const count = $("#veille-count");
    if (count) count.textContent = `${formatNumber(latest.length)} incident${latest.length > 1 ? "s" : ""}`;
    const list = $("#veille-list");
    if (list) list.innerHTML = latest.map(cardHtml).join("");
  }

  function schedule(reason) {
    lastFailure = reason || lastFailure;
    if (scheduled || rendered) return;
    scheduled = true;
    window.setTimeout(renderFailsafe, CHECK_DELAY_MS);
  }

  window.addEventListener("error", (event) => {
    schedule(event?.message || "erreur JavaScript");
  });
  window.addEventListener("unhandledrejection", (event) => {
    schedule(event?.reason?.message || "promesse rejetée");
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => schedule("rendu principal absent"), { once: true });
  } else {
    schedule("rendu principal absent");
  }
})();
