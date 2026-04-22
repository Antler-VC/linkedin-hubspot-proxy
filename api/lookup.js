export const config = { runtime: "edge" };

const HUBSPOT_PAT = process.env.HUBSPOT_PAT;
const MIN_CLIENT_VERSION = process.env.MIN_CLIENT_VERSION || "3.0.0";
const POSTHOG_API_KEY = process.env.POSTHOG_API_KEY;

// USERS: JSON map of { "email@antler.co": "assigned-password" }
let USERS = {};
try {
  USERS = JSON.parse(process.env.USERS || "{}");
} catch {
  console.error("USERS env var is not valid JSON");
}

// ── Rate limiting ────────────────────────────────────────────────────────────
// Dual sliding window: per-IP and per-user. Both must pass.
const RATE_LIMIT = 60;
const RATE_WINDOW_MS = 60_000;
const ipRateLimitMap = new Map();
const userRateLimitMap = new Map();

function checkRateLimit(map, key) {
  const now = Date.now();
  const window = (map.get(key) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (window.length >= RATE_LIMIT) return false;
  window.push(now);
  map.set(key, window);
  return true;
}

// ── Auth ─────────────────────────────────────────────────────────────────────
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function authenticate(email, password) {
  if (!email || !password) return false;
  const stored = USERS[email.toLowerCase()];
  if (!stored) return false;
  return timingSafeEqual(password, stored);
}

// ── Version check ─────────────────────────────────────────────────────────────
function meetsMinVersion(version, min) {
  const parse = (v) => (v || "0").split(".").map(Number);
  const [aj, an, ap] = parse(version);
  const [bj, bn, bp] = parse(min);
  if (aj !== bj) return aj > bj;
  if (an !== bn) return an > bn;
  return ap >= bp;
}

// ── Region ───────────────────────────────────────────────────────────────────
function getRegion() {
  const m = HUBSPOT_PAT.match(/^pat-(\w+)-/);
  if (m && m[1] !== "na1") return `app-${m[1]}`;
  return "app";
}

// ── Cache: portal ID ─────────────────────────────────────────────────────────
let cachedPortalId = null;
let cachedPortalIdKey = null;
async function getPortalId() {
  if (cachedPortalId && cachedPortalIdKey === HUBSPOT_PAT) return cachedPortalId;
  const data = await hsFetch("/account-info/v3/details");
  cachedPortalId = data.portalId;
  cachedPortalIdKey = HUBSPOT_PAT;
  return cachedPortalId;
}

// ── Cache: location labels ───────────────────────────────────────────────────
let cachedLocationLabels = null;
let cachedLocationLabelsKey = null;
async function getLocationLabels() {
  if (cachedLocationLabels && cachedLocationLabelsKey === HUBSPOT_PAT) return cachedLocationLabels;
  try {
    const prop = await hsFetch("/crm/v3/properties/deals/location_choice");
    cachedLocationLabels = {};
    for (const opt of prop.options || []) {
      cachedLocationLabels[opt.value] = opt.label;
    }
  } catch {
    cachedLocationLabels = {};
  }
  cachedLocationLabelsKey = HUBSPOT_PAT;
  return cachedLocationLabels;
}

// ── CORS ─────────────────────────────────────────────────────────────────────
function getCorsHeaders(req) {
  const origin = req?.headers?.get("origin") || "";
  const allowed = origin.endsWith(".linkedin.com") ? origin : "https://www.linkedin.com";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-User-Email, X-User-Password, X-Timestamp, X-Client-Version",
  };
}

function json(data, status = 200, req = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
  });
}

// ── Tracking: stdout audit log + PostHog capture ─────────────────────────────
// Returns a Promise so the caller can pass it to ctx.waitUntil() —
// PostHog fires after the response is sent, adding zero latency.
function track(ip, user, slug, result, startMs, clientVersion) {
  const ms = Date.now() - startMs;
  const ts = new Date().toISOString();

  console.log(JSON.stringify({ ts, ip, user: user || "unknown", slug, result, ms }));

  if (!POSTHOG_API_KEY) return Promise.resolve();

  return fetch("https://eu.i.posthog.com/capture/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      api_key: POSTHOG_API_KEY,
      event: "lookup_request",
      distinct_id: user || "unknown",
      timestamp: ts,
      properties: {
        result,
        slug: slug || null,
        ms,
        ip,
        client_version: clientVersion || null,
      },
    }),
  }).catch(() => {}); // Non-fatal: never block on analytics
}

// ── LinkedIn slug normalization ───────────────────────────────────────────────
function normalizeSlug(url) {
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

// ── HubSpot API ───────────────────────────────────────────────────────────────
async function hsFetch(path, options = {}) {
  const res = await fetch(`https://api.hubapi.com${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${HUBSPOT_PAT}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HubSpot ${res.status}: ${text}`);
  }
  return res.json();
}

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req, ctx) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: getCorsHeaders(req) });
  }

  if (req.method !== "POST") {
    return json({ error: "POST only" }, 405, req);
  }

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";
  const startMs = Date.now();
  const clientVersion = req.headers.get("x-client-version") || "0.0.0";
  const wt = (p) => ctx?.waitUntil?.(p); // fire-and-forget helper

  // Version check
  if (!meetsMinVersion(clientVersion, MIN_CLIENT_VERSION)) {
    wt(track(ip, null, null, "outdated_client", startMs, clientVersion));
    return json({ error: "Client out of date — reinstall the script" }, 426, req);
  }

  // Timestamp validation — reject requests older than 5 minutes
  const tsHeader = req.headers.get("x-timestamp");
  const tsMs = tsHeader ? new Date(tsHeader).getTime() : 0;
  if (!tsHeader || isNaN(tsMs) || Math.abs(Date.now() - tsMs) > 5 * 60 * 1000) {
    wt(track(ip, null, null, "invalid_timestamp", startMs, clientVersion));
    return json({ error: "Request expired" }, 401, req);
  }

  // Per-IP rate limit
  if (!checkRateLimit(ipRateLimitMap, ip)) {
    wt(track(ip, null, null, "rate_limited_ip", startMs, clientVersion));
    return json({ error: "Too many requests" }, 429, req);
  }

  // Auth: email + password
  const email = (req.headers.get("x-user-email") || "").toLowerCase().trim();
  const password = req.headers.get("x-user-password") || "";
  if (!authenticate(email, password)) {
    wt(track(ip, email || null, null, "unauthorized", startMs, clientVersion));
    return json({ error: "Unauthorized" }, 401, req);
  }

  // Per-user rate limit
  if (!checkRateLimit(userRateLimitMap, email)) {
    wt(track(ip, email, null, "rate_limited_user", startMs, clientVersion));
    return json({ error: "Too many requests" }, 429, req);
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400, req);
  }

  const { slug } = body;
  if (!slug || typeof slug !== "string" || slug.length > 100 || !/^[a-z0-9._-]+$/i.test(slug)) {
    return json({ error: "Invalid slug" }, 400, req);
  }

  try {
    const searchData = await hsFetch("/crm/v3/objects/contacts/search", {
      method: "POST",
      body: JSON.stringify({
        filterGroups: [
          {
            filters: [
              {
                propertyName: "linkedin_profile",
                operator: "CONTAINS_TOKEN",
                value: slug,
              },
            ],
          },
        ],
        properties: ["linkedin_profile", "hs_object_id", "hs_lastmodifieddate"],
        limit: 5,
      }),
    });

    // Collect all contacts matching the slug, sorted by last modified descending
    const contacts = (searchData.results || [])
      .filter((c) => normalizeSlug(c.properties.linkedin_profile || "") === slug)
      .sort((a, b) => {
        const aDate = new Date(a.properties.hs_lastmodifieddate || 0).getTime();
        const bDate = new Date(b.properties.hs_lastmodifieddate || 0).getTime();
        return bDate - aDate;
      });

    if (contacts.length === 0) {
      wt(track(ip, email, slug, "not_found", startMs, clientVersion));
      return json({ found: false }, 200, req);
    }

    const portalId = await getPortalId();
    const region = getRegion();

    // Fetch deal associations for all matching contacts in parallel
    let allDealIds = [];
    let contactIdWithDeals = null;
    try {
      const assocResults = await Promise.all(
        contacts.map((c) =>
          hsFetch(`/crm/v4/objects/contacts/${c.properties.hs_object_id}/associations/deals`)
            .then((d) => ({ contactId: c.properties.hs_object_id, dealIds: (d.results || []).map((r) => r.toObjectId) }))
            .catch(() => ({ contactId: c.properties.hs_object_id, dealIds: [] }))
        )
      );

      for (const { contactId, dealIds } of assocResults) {
        if (dealIds.length > 0 && !contactIdWithDeals) contactIdWithDeals = contactId;
        allDealIds.push(...dealIds);
      }
    } catch {
      // Non-fatal: fall through with no deals
    }

    // Prefer the most-recently-updated contact that has deals; fall back to most recent overall
    const primaryContactId = contactIdWithDeals || contacts[0].properties.hs_object_id;
    const hubspotUrl = `https://${region}.hubspot.com/contacts/${portalId}/record/0-1/${primaryContactId}`;

    let dealLocations = [];
    const uniqueDealIds = [...new Set(allDealIds)];
    if (uniqueDealIds.length > 0) {
      try {
        const dealsData = await hsFetch("/crm/v3/objects/deals/batch/read", {
          method: "POST",
          body: JSON.stringify({
            inputs: uniqueDealIds.map((id) => ({ id: String(id) })),
            properties: ["location_choice"],
          }),
        });

        const rawLocations = (dealsData.results || [])
          .map((d) => d.properties.location_choice)
          .filter(Boolean);

        const labels = await getLocationLabels();
        dealLocations = [...new Set(rawLocations)].map((v) => labels[v] || v);
      } catch {
        // Non-fatal: return contact without deals
      }
    }

    wt(track(ip, email, slug, "found", startMs, clientVersion));
    return json({ found: true, hubspotUrl, contactId: primaryContactId, dealLocations }, 200, req);
  } catch (err) {
    console.error("Lookup error:", err.message);
    wt(track(ip, email, slug, "error", startMs, clientVersion));
    return json({ error: "Lookup failed" }, 502, req);
  }
}
