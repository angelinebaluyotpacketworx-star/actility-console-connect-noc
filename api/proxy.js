// Vercel serverless function -- same-origin CORS proxy for the NOC dashboard.
//
// ThingPark and Console Connect don't reliably send back an
// Access-Control-Allow-Origin header, so a direct browser fetch() to their
// APIs gets silently blocked by the browser's CORS check -- previously
// worked around with a CORS-unblock browser extension on every operator's
// machine. This function sits at the same origin as the dashboard page, so
// the *browser* never has to cross an origin to reach it (no CORS check
// applies at all to a same-origin request). This function then makes the
// real request to ThingPark/Console Connect itself, server-side -- where
// CORS doesn't apply, because CORS is a browser-enforced restriction, not a
// server-side one -- and relays the response back to the browser untouched
// (status code, content-type, and body).
//
// Deployed automatically at /api/proxy on Vercel (any file under /api/ is
// auto-detected as a serverless function, zero config needed). The
// dashboard's corsFetch() helper in index.html calls this by default.
//
// Request contract (POST only):
//   { "url": "https://target-host/path", "method": "GET"|"POST"|...,
//     "headers": { ... }, "body": "raw string body, optional" }
// Response: whatever the upstream target returned (status/content-type/body
// passed through as-is), or a 4xx/502 JSON error if the request itself was
// invalid or the upstream was unreachable.

// Basic SSRF guard: only proxy to http(s) targets, and refuse anything that
// looks like it's pointed at localhost/loopback or a private/internal IP
// range. This is an *internal NOC tool* proxy, not a general-purpose open
// relay -- without this, anyone who found the URL could use it to probe
// this Vercel deployment's own internal network.
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === '0.0.0.0' || h === '::1' || h === '[::1]') return true;
  // IPv4 literal checks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16)
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [parseInt(m[1], 10), parseInt(m[2], 10)];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}

module.exports = async function handler(req, res) {
  // CORS headers on our own response (harmless for the default same-origin
  // case, and what makes it work at all if someone points corsFetch at a
  // proxy hosted on a different origin -- e.g. an internal-server operator
  // running their own instance of this function elsewhere).
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Use POST' });
    return;
  }

  let payload = req.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); }
    catch (e) { res.status(400).json({ error: 'Invalid JSON body' }); return; }
  }
  const { url, method, headers, body } = payload || {};
  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Missing "url" field' });
    return;
  }

  let target;
  try { target = new URL(url); }
  catch (e) { res.status(400).json({ error: 'Invalid url' }); return; }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    res.status(400).json({ error: `Unsupported protocol: ${target.protocol}` });
    return;
  }
  if (isBlockedHost(target.hostname)) {
    res.status(403).json({ error: `Host not allowed: ${target.hostname}` });
    return;
  }

  const reqMethod = (method || 'GET').toUpperCase();
  try {
    const upstream = await fetch(url, {
      method: reqMethod,
      headers: headers || {},
      body: (reqMethod !== 'GET' && reqMethod !== 'HEAD') ? body : undefined
    });
    const text = await upstream.text();
    res.status(upstream.status);
    const ct = upstream.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);
    res.send(text);
  } catch (err) {
    res.status(502).json({ error: 'Upstream request failed', detail: String((err && err.message) || err) });
  }
};
