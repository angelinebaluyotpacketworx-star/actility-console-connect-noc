#!/usr/bin/env python3
"""
cors_proxy_server.py -- standalone CORS proxy for the Actility x Console
Connect NOC dashboard, for use on an internal-server deployment (no
Vercel-style serverless functions available).

ThingPark and Console Connect don't reliably send back an
Access-Control-Allow-Origin header, so a direct browser fetch() to their
APIs gets silently blocked by the browser's CORS check -- previously worked
around with a CORS-unblock browser extension on every operator's machine.
This script makes that unnecessary: it runs *this* request server-side
(where CORS doesn't apply -- CORS is a browser-only restriction) and sends
the response back to the browser with its own Access-Control-Allow-Origin
header, which the browser accepts because THIS server is the one being
asked, not ThingPark/Console Connect directly.

Standard library only -- no pip install needed. Works with any Python 3.7+.

USAGE
  python cors_proxy_server.py [port]      # default port 8787

Then, in the dashboard's Live Coverage tab, set "CORS Proxy URL" to this
script's address, e.g.:
  http://<this-server-host>:8787/api/proxy

Leave "CORS Proxy URL" blank instead if you're on the Vercel deployment --
that one already has this same proxy built in as api/proxy.js and needs no
extra setup.

DEPLOYMENT NOTE
  Run this as a standing background service (Windows: NSSM or Task
  Scheduler "at startup"; Linux: systemd unit or `nohup ... &`) so it's
  always available whenever operators load the dashboard -- it does not
  need to run on the same machine that serves the HTML file, only
  somewhere reachable over the network from operators' browsers.
"""

import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DEFAULT_PORT = 8787
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB request-body ceiling


def is_blocked_host(hostname: str) -> bool:
    """Basic SSRF guard: refuse to proxy to localhost/loopback or private/
    internal IP ranges. This is an internal NOC-tool proxy, not a general-
    purpose open relay -- without this check, anyone who found this
    server's address could use it to probe its own local network."""
    host = (hostname or "").lower().strip("[]")
    if host in ("localhost", "0.0.0.0", "::1"):
        return True
    if host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass  # not a literal IP -- resolve the hostname and check that instead
    try:
        resolved = socket.gethostbyname(host)
        ip = ipaddress.ip_address(resolved)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except (socket.gaierror, ValueError):
        return False  # couldn't resolve -- let the real request fail naturally


class ProxyHandler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        # Handy for a quick "is this running" check in a browser -- not part
        # of the actual proxy contract, which is POST /api/proxy only.
        if self.path in ("/", "/health"):
            body = b'{"status":"ok","proxy_path":"/api/proxy"}'
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self._set_cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path != "/api/proxy":
            self.send_response(404)
            self._set_cors_headers()
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(400, {"error": "Missing or oversized request body"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        url = payload.get("url")
        method = (payload.get("method") or "GET").upper()
        headers = payload.get("headers") or {}
        body = payload.get("body")

        if not url or not isinstance(url, str):
            self._send_json(400, {"error": 'Missing "url" field'})
            return

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            self._send_json(400, {"error": f"Unsupported protocol: {parsed.scheme}"})
            return
        if is_blocked_host(parsed.hostname or ""):
            self._send_json(403, {"error": f"Host not allowed: {parsed.hostname}"})
            return

        data = body.encode("utf-8") if (body and method not in ("GET", "HEAD")) else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=30) as upstream:
                self._relay(upstream.status, upstream.getheader("Content-Type"), upstream.read())
        except urllib.error.HTTPError as e:
            # Still a real response from the upstream server -- relay its
            # status/body as-is rather than treating it as a proxy failure.
            self._relay(e.code, e.headers.get("Content-Type") if e.headers else None, e.read())
        except Exception as e:
            self._send_json(502, {"error": "Upstream request failed", "detail": str(e)})

    def _relay(self, status, content_type, body_bytes):
        self.send_response(status)
        self._set_cors_headers()
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[cors_proxy_server] {self.address_string()} - {fmt % args}\n")


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}", file=sys.stderr)
            sys.exit(1)
    server = ThreadingHTTPServer(("0.0.0.0", port), ProxyHandler)
    print(f"cors_proxy_server listening on 0.0.0.0:{port} -- POST /api/proxy")
    print(f"Point the dashboard's \"CORS Proxy URL\" field at: http://<this-host>:{port}/api/proxy")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
