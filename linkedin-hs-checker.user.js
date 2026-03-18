// ==UserScript==
// @name         LinkedIn HubSpot Checker
// @namespace    https://github.com/gentian
// @version      2.0.3
// @description  Check if LinkedIn profiles exist in HubSpot CRM
// @match        *://*.linkedin.com/in/*
// @match        *://*.linkedin.com/pub/*
// @match        *://*.linkedin.com/search/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @connect      linkedin-hubspot-proxy.vercel.app
// @run-at       document-idle
// @downloadURL  https://gist.githubusercontent.com/gentiku/ac356575470efb329052ebf236d1d437/raw/linkedin-hs-checker.user.js
// @updateURL    https://gist.githubusercontent.com/gentiku/ac356575470efb329052ebf236d1d437/raw/linkedin-hs-checker.user.js
// ==/UserScript==

(function () {
  "use strict";

  // ── Config ──────────────────────────────────────────────────────────
  const PROXY_URL = "https://linkedin-hubspot-proxy.vercel.app/api/lookup";
  const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

  // Proxy secret stored in Violentmonkey local storage
  let PROXY_SECRET = GM_getValue("proxy_secret", "");
  if (!PROXY_SECRET) {
    PROXY_SECRET = prompt("LinkedIn HubSpot Checker: Enter the proxy secret (ask Gentian)");
    if (PROXY_SECRET) {
      GM_setValue("proxy_secret", PROXY_SECRET);
    } else {
      return; // Can't work without secret
    }
  }

  // ── Cache ───────────────────────────────────────────────────────────
  const cache = new Map();

  function cacheGet(slug) {
    const entry = cache.get(slug);
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL) {
      cache.delete(slug);
      return null;
    }
    return entry.data;
  }

  function cacheSet(slug, data) {
    cache.set(slug, { data, ts: Date.now() });
  }

  // ── Rate Limiter ──────────────────────────────────────────────────
  const MAX_CONCURRENT = 3;
  let activeRequests = 0;
  const requestQueue = [];

  function enqueueRequest(fn) {
    return new Promise((resolve, reject) => {
      requestQueue.push({ fn, resolve, reject });
      processQueue();
    });
  }

  function processQueue() {
    while (activeRequests < MAX_CONCURRENT && requestQueue.length > 0) {
      const { fn, resolve, reject } = requestQueue.shift();
      activeRequests++;
      fn()
        .then(resolve)
        .catch(reject)
        .finally(() => {
          activeRequests--;
          processQueue();
        });
    }
  }

  function debounce(fn, ms) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), ms);
    };
  }

  // ── URL Parser ──────────────────────────────────────────────────────
  function extractSlug(url) {
    try {
      if (!url.startsWith("http")) url = "https://" + url;
      const parsed = new URL(url);
      if (!parsed.hostname.endsWith("linkedin.com")) return null;
      const parts = parsed.pathname.split("/").filter(Boolean);
      const inIdx = parts.indexOf("in");
      if (inIdx !== -1 && parts[inIdx + 1]) return parts[inIdx + 1].toLowerCase();
      const pubIdx = parts.indexOf("pub");
      if (pubIdx !== -1 && parts[pubIdx + 1]) return parts[pubIdx + 1].toLowerCase();
      return null;
    } catch {
      const m = url.match(/\/(?:in|pub)\/([^/?#]+)/i);
      return m ? m[1].toLowerCase() : null;
    }
  }

  // ── Proxy Caller ────────────────────────────────────────────────────
  function lookupSlug(slug) {
    const cached = cacheGet(slug);
    if (cached) return Promise.resolve(cached);

    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: "POST",
        url: PROXY_URL,
        headers: {
          "Content-Type": "application/json",
          "X-Proxy-Secret": PROXY_SECRET,
        },
        data: JSON.stringify({ slug }),
        responseType: "json",
        onload(res) {
          if (res.status >= 200 && res.status < 300) {
            const data = typeof res.response === "string" ? JSON.parse(res.response) : res.response;
            cacheSet(slug, data);
            resolve(data);
          } else {
            let errMsg = `HTTP ${res.status}`;
            try {
              const body = typeof res.response === "string" ? JSON.parse(res.response) : res.response;
              if (body && body.error) errMsg = body.error;
            } catch {}
            reject(new Error(errMsg));
          }
        },
        onerror() {
          reject(new Error("Network error"));
        },
      });
    });
  }

  // ── SVG Icon ────────────────────────────────────────────────────────
  const HS_SPROCKET = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M17.63 9.22V7.08a1.79 1.79 0 0 0 1.03-1.61V5.4a1.79 1.79 0 0 0-1.79-1.79h-.07a1.79 1.79 0 0 0-1.79 1.79v.07c0 .7.41 1.3 1 1.59v2.16a4.6 4.6 0 0 0-2.15 1.13l-5.7-4.44a2.07 2.07 0 0 0 .06-.47 2.1 2.1 0 1 0-2.1 2.1c.43 0 .82-.14 1.16-.36l5.58 4.34a4.63 4.63 0 0 0 .2 5.19l-1.72 1.72a1.51 1.51 0 0 0-.44-.07 1.53 1.53 0 1 0 1.53 1.53c0-.16-.03-.3-.07-.44l1.7-1.7A4.63 4.63 0 1 0 17.63 9.22ZM16.87 15.5a2.75 2.75 0 1 1 0-5.5 2.75 2.75 0 0 1 0 5.5Z" fill="currentColor"/></svg>`;

  // ── Styles ──────────────────────────────────────────────────────────
  const STYLE = document.createElement("style");
  STYLE.textContent = `
    #hs-badge {
      position: fixed;
      top: 70px;
      right: 20px;
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      font-weight: 600;
      line-height: 1.3;
    }
    #hs-badge .hs-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 14px;
      border-radius: 24px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }
    #hs-badge .hs-pill--loading {
      background: #f5f8fa;
      border: 1px solid #dfe3eb;
      color: #7c98b6;
    }
    #hs-badge .hs-pill--loading svg { color: #f5a623; }
    #hs-badge .hs-pill--found {
      background: #ff7a59;
      border: 1px solid #ff7a59;
      color: #fff;
      cursor: pointer;
    }
    #hs-badge .hs-pill--found:hover { background: #ff5c35; }
    #hs-badge .hs-pill--found svg { color: #fff; }
    #hs-badge .hs-pill--not-found {
      background: #fff;
      border: 1px solid #cbd6e2;
      color: #7c98b6;
    }
    #hs-badge .hs-pill--not-found svg { color: #99acc2; }
    #hs-badge .hs-pill--error {
      background: #fff;
      border: 1px solid #f2545b;
      color: #f2545b;
    }
    #hs-badge .hs-pill--error svg { color: #f2545b; }

    .hs-search-tag {
      display: inline-flex;
      align-items: center;
      gap: 3px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 11px;
      font-weight: 600;
      padding: 1px 8px;
      border-radius: 10px;
      margin-left: 6px;
      vertical-align: middle;
      line-height: 18px;
    }
    .hs-search-tag--found {
      background: #ff7a59;
      color: #fff;
      cursor: pointer;
    }
    .hs-search-tag--found:hover { background: #ff5c35; }
    .hs-search-tag svg { width: 10px; height: 10px; }
  `;
  document.head.appendChild(STYLE);

  // ── Profile Badge ───────────────────────────────────────────────────
  function removeBadge() {
    const el = document.getElementById("hs-badge");
    if (el) el.remove();
    // Also remove old Chrome extension badge if present
    const old = document.getElementById("hs-crm-badge");
    if (old) old.remove();
  }

  function showBadge(state, text, href) {
    removeBadge();

    const wrap = document.createElement("div");
    wrap.id = "hs-badge";

    const pill = document.createElement("div");
    pill.className = `hs-pill hs-pill--${state}`;
    const icon = document.createElement("span");
    icon.innerHTML = HS_SPROCKET;
    const label = document.createElement("span");
    label.textContent = text;
    pill.appendChild(icon);
    pill.appendChild(label);

    if (state === "found" && href) {
      pill.addEventListener("click", () => window.open(href, "_blank"));
    }

    wrap.appendChild(pill);
    document.body.appendChild(wrap);
  }

  // ── Profile Page Check ──────────────────────────────────────────────
  let currentProfileUrl = "";

  function checkProfile() {
    const url = window.location.href;
    if (!url.match(/linkedin\.com\/(?:in|pub)\/[^/]+/)) {
      removeBadge();
      return;
    }
    if (url === currentProfileUrl) return;
    currentProfileUrl = url;

    const slug = extractSlug(url);
    if (!slug) {
      removeBadge();
      return;
    }

    showBadge("loading", "Checking HubSpot...", null);

    lookupSlug(slug)
      .then((data) => {
        if (data.found) {
          const locs = data.dealLocations || [];
          const text = locs.length > 0
            ? `Deal in: ${locs.join(", ")}`
            : "Contact exists";
          showBadge("found", text, data.hubspotUrl);
        } else {
          showBadge("not-found", "Not in HubSpot", null);
        }
      })
      .catch((err) => {
        showBadge("error", err.message, null);
      });
  }

  // ── Search Results Indicators ───────────────────────────────────────
  const PROCESSED_ATTR = "data-hs-checked";

  function processSearchResults() {
    if (!window.location.href.includes("/search/results/people")) return;

    // LinkedIn search result cards contain profile links in spans/anchors
    const links = document.querySelectorAll(
      '.reusable-search__result-container a[href*="/in/"]'
    );

    links.forEach((link) => {
      // Find the closest result container to avoid duplicate tags
      const container = link.closest(".reusable-search__result-container");
      if (!container || container.getAttribute(PROCESSED_ATTR)) return;
      container.setAttribute(PROCESSED_ATTR, "1");

      const slug = extractSlug(link.href);
      if (!slug) return;

      enqueueRequest(() => lookupSlug(slug))
        .then((data) => {
          if (!data.found) return;

          // Find the name element to append tag next to
          const nameEl =
            container.querySelector(".entity-result__title-text a span[dir]") ||
            container.querySelector(".entity-result__title-text a") ||
            container.querySelector('a[href*="/in/"] span');
          if (!nameEl) return;

          // Don't double-add
          if (nameEl.parentElement.querySelector(".hs-search-tag")) return;

          const tag = document.createElement("span");
          tag.className = "hs-search-tag hs-search-tag--found";
          const tagIcon = document.createElement("span");
          tagIcon.innerHTML = HS_SPROCKET;
          tag.appendChild(tagIcon);
          tag.appendChild(document.createTextNode(" HS"));
          tag.title = data.dealLocations.length
            ? `In HubSpot | ${data.dealLocations.join(", ")}`
            : "In HubSpot";
          tag.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            window.open(data.hubspotUrl, "_blank");
          });

          nameEl.parentElement.appendChild(tag);
        })
        .catch(() => {
          // Silent fail for search results
        });
    });
  }

  // ── SPA Observer ────────────────────────────────────────────────────
  let lastHref = window.location.href;

  function onNavigate() {
    const url = window.location.href;
    if (url === lastHref) return;
    lastHref = url;
    currentProfileUrl = "";

    if (url.match(/linkedin\.com\/(?:in|pub)\/[^/]+/)) {
      checkProfile();
    } else {
      removeBadge();
    }

    if (url.includes("/search/results/people")) {
      // Small delay to let DOM render
      setTimeout(processSearchResults, 800);
    }
  }

  const debouncedSearchProcess = debounce(processSearchResults, 500);

  const observer = new MutationObserver(() => {
    onNavigate();

    // Reprocess search results on DOM changes (pagination/scroll), debounced
    if (window.location.href.includes("/search/results/people")) {
      debouncedSearchProcess();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // ── Init ────────────────────────────────────────────────────────────
  if (window.location.href.match(/linkedin\.com\/(?:in|pub)\/[^/]+/)) {
    checkProfile();
  }
  if (window.location.href.includes("/search/results/people")) {
    setTimeout(processSearchResults, 1000);
  }
})();
