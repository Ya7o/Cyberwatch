/* Cyberwatch — tendance glissante sur 12 mois, alignée sur le KPI activité. */
(() => {
  "use strict";

  const DAY = 864e5;
  const OCEAN_LOCATIONS = new Set([
    "La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores",
  ]);
  let incidents = [];
  let timer = null;

  const $ = (selector) => document.querySelector(selector);

  function normalize(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase("fr-FR")
      .trim();
  }

  function incidentDate(incident) {
    const date = new Date(incident?.date);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function filteredRows() {
    const org = normalize($("#f-org")?.value);
    const source = $("#f-source")?.value || "";
    const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
    const local = $("#f-local")?.getAttribute("aria-pressed") === "true";

    return incidents.filter((incident) => {
      if (source && !(incident.sources || []).includes(source)) return false;
      if (ocean && !OCEAN_LOCATIONS.has(incident.location)) return false;
      if (local && !incident.local) return false;
      if (org && !normalize(incident.org).includes(org)) return false;
      return true;
    });
  }

  function countBetween(rows, start, end) {
    return rows.reduce((count, incident) => {
      const date = incidentDate(incident);
      return date && date >= start && date < end ? count + 1 : count;
    }, 0);
  }

  function render() {
    const node = $("#kpi-12m-trend");
    if (!node || !incidents.length) return;

    const rows = filteredRows();
    const now = new Date();
    const end = new Date(now.getTime() + 1);
    const currentStart = new Date(now.getTime() - 365 * DAY);
    const previousStart = new Date(now.getTime() - 730 * DAY);
    const current = countBetween(rows, currentStart, end);
    const previous = countBetween(rows, previousStart, currentStart);

    if (previous === 0) {
      node.textContent = current === 0
        ? "Stable vs 12 mois précédents"
        : "Nouvelle activité vs 12 mois précédents";
      node.dataset.direction = current === 0 ? "flat" : "up";
      return;
    }

    const percent = Math.round(((current - previous) / previous) * 100);
    const sign = percent > 0 ? "+" : "";
    node.textContent = `${sign}${percent} % vs 12 mois précédents`;
    node.dataset.direction = percent > 0 ? "up" : percent < 0 ? "down" : "flat";
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(render, 220);
  }

  async function init() {
    try {
      const response = await fetch("assets/data/incidents.json", { cache: "no-cache" });
      if (!response.ok) throw new Error(String(response.status));
      const data = await response.json();
      incidents = Array.isArray(data) ? data : [];
    } catch (error) {
      console.warn("Tendance 12 mois indisponible", error);
      return;
    }

    ["#f-org", "#f-source", "#f-ocean-indien", "#f-local", "#f-reset"].forEach((selector) => {
      const control = $(selector);
      if (!control) return;
      control.addEventListener("input", schedule);
      control.addEventListener("change", schedule);
      control.addEventListener("click", schedule);
    });

    render();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
