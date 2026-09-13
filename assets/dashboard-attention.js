/* Cyberwatch — mise en évidence conservative des incidents à surveiller.
 *
 * Ce module n'invente pas un score de gravité. Il s'appuie uniquement sur les
 * informations déjà rendues par le dashboard : exposition forte documentée et,
 * à défaut, menace offensive corroborée par plusieurs sources.
 */
(() => {
  "use strict";

  const STRONG_EXPOSURE = new Map([
    ["Identifiants ou secrets exposés", "Identifiants ou secrets exposés"],
    ["Données très sensibles signalées", "Données très sensibles signalées"],
  ]);
  const OFFENSIVE_THREAT = /^(intrusion|phishing\s*\/\s*fraude|malware|rançongiciel|ransomware)$/i;
  const CONTAINERS = ["#veille-list", "#focus-body", "#s-list"];

  function text(node) {
    return String(node?.textContent || "").trim();
  }

  function attentionReasons(card) {
    const tags = Array.from(card.querySelectorAll(".incident-tags > span")).map(text).filter(Boolean);
    const reasons = [];

    for (const [label, reason] of STRONG_EXPOSURE) {
      if (tags.includes(label)) reasons.push(reason);
    }

    const threat = tags[0] || "";
    const sourceCount = card.querySelectorAll(".incident-source-badges > *").length;
    if (!reasons.length && sourceCount >= 2 && OFFENSIVE_THREAT.test(threat)) {
      reasons.push(`Menace ${threat.toLowerCase()} corroborée par ${sourceCount} sources`);
    }

    return reasons;
  }

  function decorateCard(card) {
    const reasons = attentionReasons(card);
    const current = card.querySelector(".incident-attention");

    if (!reasons.length) {
      delete card.dataset.attention;
      current?.remove();
      return;
    }

    card.dataset.attention = "watch";
    const top = card.querySelector(".incident-card-top");
    if (!top) return;

    const marker = current || document.createElement("span");
    marker.className = "incident-attention";
    marker.textContent = "À surveiller";
    marker.title = reasons.join(" · ");
    marker.setAttribute("aria-label", `À surveiller : ${reasons.join(" ; ")}`);
    if (!current) top.appendChild(marker);
  }

  function decorate(root = document) {
    root.querySelectorAll?.(".incident-card").forEach(decorateCard);
  }

  function observeContainer(container) {
    decorate(container);
    new MutationObserver(() => decorate(container)).observe(container, {
      childList: true,
      subtree: true,
    });
  }

  function init() {
    CONTAINERS.map((selector) => document.querySelector(selector)).filter(Boolean).forEach(observeContainer);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true });
  else init();
})();
