# What a run controller's endpoint has to do with a nullfield signal: check
# the signature over timestamp and body, refuse stale timestamps, then act.
# Shared by demos 19 (mesh) and 20 (proxy).
import hashlib, hmac, http.server, json, time

secret = open("/etc/signal/secret", "rb").read().strip()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ts = self.headers.get("X-Nullfield-Timestamp", "")
        want = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        fresh = ts.isdigit() and abs(time.time() - int(ts)) < 300
        if not (fresh and hmac.compare_digest(want, self.headers.get("X-Nullfield-Signature", ""))):
            print(json.dumps({"msg": "rejected"}), flush=True)
            self.send_response(401)
            self.end_headers()
            return
        e = json.loads(body)
        print(json.dumps({"msg": "verified", "type": e.get("type"),
                          "run_id": e.get("run_id"), "session_id": e.get("session_id")}), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("", 8080), Handler).serve_forever()
