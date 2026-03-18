export const config = { runtime: "edge" };

const HUBSPOT_PAT = process.env.HUBSPOT_PAT;
const PROXY_SECRET = process.env.PROXY_SECRET;

// Derive region from PAT prefix (pat-eu1-xxx → app-eu1, pat-na1-xxx → app)
function getRegion() {
  const m = HUBSPOT_PAT.match(/^pat-(\w+)-/);
  if (m && m[1] !== "na1") return `app-${m[1]}`;
  return "app";
}

// Cache portal ID after first fetch
let cachedPortalId = null;
async function getPortalId() {
  if (cachedPortalId) return cachedPortalId;
  const data = await hsFetch("/account-info/v3/details");
  cachedPortalId = data.portalId;
  return cachedPortalId;
}

// Cache location_choice value→label map
let cachedLocationLabels = null;
async function getLocationLabels() {
  if (cachedLocationLabels) return cachedLocationLabels;
  try {
    const prop = await hsFetch("/crm/v3/properties/deals/location_choice");
    cachedLocationLabels = {};
    for (const opt of prop.options || []) {
      cachedLocationLabels[opt.value] = opt.label;
    }
  } catch {
    cachedLocationLabels = {};
  }
  return cachedLocationLabels;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Proxy-Secret",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

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

export default async function handler(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "POST") {
    return json({ error: "POST only" }, 405);
  }

  const secret = req.headers.get("x-proxy-secret");
  if (!secret || secret !== PROXY_SECRET) {
    return json({ error: "Unauthorized" }, 401);
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { slug } = body;
  if (!slug || typeof slug !== "string") {
    return json({ error: "Missing slug" }, 400);
  }

  try {
    // 1. Search for contact by linkedin_profile
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
        properties: ["linkedin_profile", "hs_object_id"],
        limit: 5,
      }),
    });

    // Verify slug match
    const contact = (searchData.results || []).find((c) => {
      const stored = c.properties.linkedin_profile || "";
      const storedSlug = normalizeSlug(stored);
      return storedSlug === slug;
    });

    if (!contact) {
      return json({ found: false });
    }

    const contactId = contact.properties.hs_object_id;
    const portalId = await getPortalId();
    const hubspotUrl = `https://${getRegion()}.hubspot.com/contacts/${portalId}/record/0-1/${contactId}`;

    // 2. Get associated deals
    let dealLocations = [];
    try {
      const assocData = await hsFetch(
        `/crm/v4/objects/contacts/${contactId}/associations/deals`
      );
      const dealIds = (assocData.results || []).map((r) => r.toObjectId);

      if (dealIds.length > 0) {
        // 3. Batch read deal properties
        const dealsData = await hsFetch("/crm/v3/objects/deals/batch/read", {
          method: "POST",
          body: JSON.stringify({
            inputs: dealIds.map((id) => ({ id: String(id) })),
            properties: ["location_choice"],
          }),
        });

        const rawLocations = (dealsData.results || [])
          .map((d) => d.properties.location_choice)
          .filter(Boolean);

        // Deduplicate
        const uniqueLocations = [...new Set(rawLocations)];

        // Resolve internal values to human labels
        const labels = await getLocationLabels();
        dealLocations = uniqueLocations.map((v) => labels[v] || v);
      }
    } catch {
      // Non-fatal: return contact without deals
    }

    return json({ found: true, hubspotUrl, contactId, dealLocations });
  } catch (err) {
    return json({ error: err.message }, 502);
  }
}
