// Serve the client signing portal from nautisignal.com.
//
// The portal itself is a Supabase edge function. It cannot be linked to a client
// directly, because Supabase rewrites Content-Type to text/plain and injects a
// sandbox CSP on anything served from the shared *.supabase.co functions domain
// — an anti-phishing measure on their side. The result is that a browser renders
// the signing page as raw HTML source. Verified 2026-08-20: our own headers
// (X-Frame-Options, Referrer-Policy, Cache-Control, nosniff) all survive intact
// while Content-Type is replaced, which is what identifies it as a gateway
// rewrite rather than anything in our code.
//
// So the fix has to be on our side of the wire: proxy the function through this
// domain and set the header ourselves. That also means the client never sees a
// supabase.co URL on a page asking them to sign and pay.
//
// The portal path arrives as a ?path= query parameter put there by the rewrite
// in vercel.json, rather than through a [...catch-all] filename. A catch-all
// under api/ did not resolve on this project — /api/ping deployed fine from the
// same commit while api/agreement/[...path].js returned 404 — so the routing is
// kept in vercel.json where it is visible and behaves predictably.
//
// Content type is decided by sniffing the body rather than trusting the origin,
// because the origin's Content-Type is exactly the thing that has been
// destroyed. Two shapes matter: the signed-agreement PDF and everything else,
// which is HTML.

const ORIGIN =
  process.env.SALES_PORTAL_ORIGIN ||
  "https://yovyrzfgagqcxgwxwuqf.supabase.co/functions/v1/sales-public";

// Headers that belong to the hop, not the message. Forwarding these breaks
// things in subtle ways — a stale content-length after re-encoding, or an
// upstream that gzips because we claimed to accept it and then a body we hand
// back raw.
const STRIP_REQUEST = new Set([
  "host", "connection", "content-length", "accept-encoding",
  "x-forwarded-host", "x-forwarded-proto", "x-vercel-id",
]);

// Response headers the origin owns and we must not pass through: the mangled
// content-type, and the sandbox CSP that would blank the page even once the
// type is right.
const STRIP_RESPONSE = new Set([
  "content-type", "content-length", "content-encoding",
  "content-security-policy", "transfer-encoding", "connection",
]);

export const config = { api: { bodyParser: false } };

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// The origin's Content-Type is unusable, so identify the payload from itself.
function sniffContentType(buffer) {
  if (buffer.length >= 5 && buffer.subarray(0, 5).toString("latin1") === "%PDF-") {
    return "application/pdf";
  }
  return "text/html; charset=utf-8";
}

export default async function handler(req, res) {
  const query = { ...req.query };
  // Put there by the rewrite; everything else in the query belongs to the
  // portal (?paid=1&session_id=… on the way back from Stripe, for one).
  const rawPath = Array.isArray(query.path) ? query.path.join("/") : String(query.path || "");
  delete query.path;

  const segments = rawPath.split("/").filter(Boolean);
  // Tokens are opaque and validated upstream; this only stops a path segment
  // from climbing out of the portal's namespace.
  if (segments.some((segment) => segment === "..")) {
    res.status(400).setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.send("Bad request");
  }

  const forwarded = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item !== undefined) forwarded.append(key, String(item));
    }
  }
  const search = forwarded.toString();
  const target =
    `${ORIGIN}/${segments.map(encodeURIComponent).join("/")}${search ? `?${search}` : ""}`;

  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (!STRIP_REQUEST.has(name.toLowerCase()) && value !== undefined) {
      headers[name] = Array.isArray(value) ? value.join(", ") : value;
    }
  }

  const method = req.method || "GET";
  const body = method === "GET" || method === "HEAD" ? undefined : await readBody(req);

  let upstream;
  try {
    upstream = await fetch(target, {
      method,
      headers,
      body,
      // A 303 to Stripe Checkout has to reach the browser, not be followed here.
      redirect: "manual",
    });
  } catch (error) {
    console.error("agreement proxy failed", { target, message: error?.message });
    res.status(502).setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(
      "<!doctype html><meta charset=utf-8><title>Temporarily unavailable — NautiSignal</title>" +
      "<p style=\"font-family:system-ui;padding:40px\">This agreement page is temporarily unavailable. " +
      "Please try again in a moment, or reply to the email you received from NautiSignal.</p>"
    );
  }

  const buffer = Buffer.from(await upstream.arrayBuffer());

  for (const [name, value] of upstream.headers) {
    const lower = name.toLowerCase();
    if (STRIP_RESPONSE.has(lower)) continue;
    // Set-Cookie must stay separate; combining them loses all but one cookie.
    if (lower === "set-cookie") continue;
    res.setHeader(name, value);
  }
  const cookies = typeof upstream.headers.getSetCookie === "function"
    ? upstream.headers.getSetCookie()
    : [];
  if (cookies.length) res.setHeader("Set-Cookie", cookies);

  res.setHeader("Content-Type", sniffContentType(buffer));
  res.status(upstream.status);
  return res.send(buffer);
}
