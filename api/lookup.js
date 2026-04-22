export const config = { runtime: "edge" };

const HUBSPOT_PAT = process.env.HUBSPOT_PAT;
const PROXY_SECRET = process.env.PROXY_SECRET;

// ── Rate limiting ────────────────────────────────────────────────────────────
// In-memory per-IP sliding window. Resets across edge instance restarts.
const RATE_LIMIT = 60;
const RATE_WINDOW_MS = 60_000;
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const window = (rateLimitMap.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (window.length >= RATE_LIMIT) return false;
  window.push(now);
  rateLimitMap.set(ip, window);
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

// ── Region ───────────────────────────────────────────────────────────────────
function getRegion() {
  const m = HUBSPOT_PAT.match(/^pat-(\w+)-/);
  if (m && m[1] !== "na1") return `app-${m[1]}`;
  return "app";
}

// ── Cache: portal ID ─────────────────────────────────────────────────────────
// patKey guards against stale data if HUBSPOT_PAT changes without a redeploy
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
    "Access-Control-Allow-Headers": "Content-Type, X-Proxy-Secret",
  };
}

function json(data, status = 200, req = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
  });
}

// ── Audit log ────────────────────────────────────────────────────────────────
function audit(ip, slug, result, startMs) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    ip,
    slug,
    result,
    ms: Date.now() - startMs,
  }));
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
export default async function handler(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: getCorsHeaders(req) });
  }

  if (req.method !== "POST") {
    return json({ error: "POST only" }, 405, req);
  }

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";
  const startMs = Date.now();

  if (!checkRateLimit(ip)) {
    audit(ip, null, "rate_limited", startMs);
    return json({ error: "Too many requests" }, 429, req);
  }

  const secret = req.headers.get("x-proxy-secret");
  if (!secret || !timingSafeEqual(secret, PROXY_SECRET)) {
    audit(ip, null, "unauthorized", startMs);
    return json({ error: "Unauthorized" }, 401, req);
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
      audit(ip, slug, "not_found", startMs);
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

    audit(ip, slug, "found", startMs);
    return json({ found: true, hubspotUrl, contactId: primaryContactId, dealLocations }, 200, req);
  } catch (err) {
    console.error("Lookup error:", err.message);
    audit(ip, slug, "error", startMs);
    return json({ error: "Lookup failed" }, 502, req);
  }
}
