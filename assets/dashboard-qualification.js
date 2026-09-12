/* Cyberwatch — la qualification est un diagnostic de production.
 *
 * Le bandeau global reste réservé à la fraîcheur et à la couverture des
 * données. Un verdict de qualification PARTIAL reste visible dans Analyse >
 * Fiabilité de production, avec ses motifs détaillés.
 */
(() => {
  "use strict";

  const STATUS_PATH = "assets/data/status.json";

  function label(qualification) {
    return qualification?.label || "Qualification incomplète";
  }

  function reasonsText(qualification) {
    return (qualification?.reasons || []).filter(Boolean).join(" ; ");
  }

  function qualificationSentence(qualification) {
    const reasons = reasonsText(qualification);
    return `${label(qualification)}${reasons ? ` : ${reasons}` : ""}.`;
  }

  function removeQualificationFromGlobalAlert(qualification) {
    if (qualification?.state !== "PARTIAL") return;
    const alert = document.querySelector("#data-alert");
    const detail = document.querySelector("#data-alert-detail");
    const strong = alert?.querySelector("strong");
    if (!alert || !detail || !strong) return;

    const sentence = qualificationSentence(qualification);
    const current = String(detail.textContent || "");
    if (!current.includes(sentence)) return;

    const remaining = current.replace(sentence, "").replace(/\s{2,}/g, " ").trim();
    if (detail.textContent !== remaining) detail.textContent = remaining;

    if (!remaining) {
      alert.hidden = true;
      return;
    }

    const currentTitle = String(strong.textContent || "").trim().replace(/\.$/, "");
    const qualificationTitle = label(qualification).trim().replace(/\.$/, "");
    if (currentTitle === qualificationTitle) {
      strong.textContent = "Couverture partielle.";
      alert.dataset.status = "coverage";
    }
  }

  function renderQualificationInProduction(qualification) {
    const container = document.querySelector("#production-metrics");
    if (!container || qualification?.state !== "PARTIAL") return;
    const metric = Array.from(container.querySelectorAll(".production-metric"))
      .find((node) => node.querySelector("small")?.textContent?.trim() === "Qualification");
    const detail = metric?.querySelector("span");
    const reasons = reasonsText(qualification);
    if (detail && reasons && detail.textContent !== reasons) detail.textContent = reasons;
  }

  function installObservers(qualification) {
    const alert = document.querySelector("#data-alert");
    if (alert) {
      new MutationObserver(() => removeQualificationFromGlobalAlert(qualification)).observe(alert, {
        subtree: true,
        childList: true,
        characterData: true,
        attributes: true,
        attributeFilter: ["hidden", "data-status"],
      });
    }

    const production = document.querySelector("#production-metrics");
    if (production) {
      new MutationObserver(() => renderQualificationInProduction(qualification)).observe(production, {
        subtree: true,
        childList: true,
        characterData: true,
      });
    }

    const runPill = document.querySelector("#run-pill");
    runPill?.addEventListener("click", () => {
      window.requestAnimationFrame(() => document.querySelector("#production-title")?.scrollIntoView({ behavior: "smooth" }));
    });
  }

  async function init() {
    const response = await fetch(STATUS_PATH, { cache: "no-store" });
    if (!response.ok) throw new Error(`${STATUS_PATH}: ${response.status}`);
    const status = await response.json();
    const qualification = status?.qualification || {};
    removeQualificationFromGlobalAlert(qualification);
    renderQualificationInProduction(qualification);
    installObservers(qualification);
  }

  init().catch((error) => console.error("Cyberwatch: qualification de production indisponible", error));
})();
