#!/usr/bin/env python3
"""melissacyber HARD lab: chained vulns + flag capture (never expose it).

Chain 1 (recon->leak->forge->RCE->flag):
  /robots.txt leaks /backup/ -> /backup/config.json leaks internal secret
  -> attacker computes sha256(secret + path) as X-Internal-Auth header
  -> /admin?cmd= is cmd-injection (echo canary, cat /flag drops FLAG)

Chain 2: /api/calc?expr= evals input (expr injection -> FLAG on import)
Chain 3: /ping?host= blind cmdi -> only provable via OOB callback
Chain 4: /login SQLi auth bypass -> FLAG{auth_bypass}
"""
import http.server, urllib.parse, hashlib, json, time, threading, urllib.request, os, signal

SECRET = "pepper123"
FLAG = "FLAG{h4rd_l4b_pwnd_by_melissacyber}"

def auth(path): return hashlib.sha256((SECRET + path).encode()).hexdigest()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _r(self, body, status=200, ctype="text/html"):
        self.send_response(status); self.send_header("content-type", ctype)
        self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        g = lambda k: q.get(k,[""])[0]
        if u.path == "/":
            self._r("<html><body>ACME Corp intranet</body></html>")
        elif u.path == "/robots.txt":
            self._r("User-agent: *\nDisallow: /backup/\nDisallow: /internal-status", ctype="text/plain")
        elif u.path == "/backup/config.json":
            self._r(json.dumps({"env":"prod","internal_secret":SECRET,
                "note":"X-Internal-Auth = sha256(internal_secret + path)"}), ctype="application/json")
        elif u.path == "/internal-status":
            self._r("status: ok; workers: 4", ctype="text/plain")
        elif u.path == "/admin":
            if self.headers.get("X-Internal-Auth") != auth("/admin"):
                self._r("forbidden", 403); return
            c = g("cmd")
            if "sleep" in c:
                n = int("".join(ch for ch in c.split("sleep")[1] if ch.isdigit()) or "3")
                time.sleep(min(n,5)); self._r("done")
            elif "cat /flag" in c or "cat flag" in c:
                self._r(FLAG)
            elif "echo " in c:
                self._r(f"out: {c.split('echo ',1)[1]}")
            else:
                self._r("admin ok")
        elif u.path == "/api/calc":
            e = g("expr")
            if "import" in e or "__" in e or "popen" in e or "flag" in e:
                self._r(FLAG)  # simulated RCE via eval
            else:
                try: self._r(str(eval(e, {"__builtins__":{}}, {})))
                except Exception as ex: self._r(f"error: {ex}")
        elif u.path == "/ping":
            h = g("host")
            if ";" in h or "|" in h or "$(" in h or "`" in h:
                if "curl " in h or "wget " in h:
                    tgt = h.split("curl ",1)[-1].split("wget ",1)[-1].strip().split()[0]
                    threading.Thread(target=lambda: urllib.request.urlopen(tgt,timeout=3),daemon=True).start()
                    self._r("pong")
                elif "echo " in h:
                    self._r(f"pong {h.split('echo ',1)[1]}")
                else:
                    self._r("pong")
            else:
                self._r("pong")
        elif u.path == "/login":
            us, pw = g("u"), g("p")
            if ("'" in us and "OR" in us.upper() and "1'='1" in us) or us == "admin' --":
                self._r(f"Welcome admin! {FLAG}")
            else:
                self._r("invalid credentials", 401)
        elif u.path == "/flag":
            self._r("you wish", 404)
        else:
            self._r("nope", 404)

if __name__ == "__main__":
    port = int(os.environ.get("PORT","8898"))
    print(f"hard lab on :{port}")
    http.server.HTTPServer(("127.0.0.1",port),H).serve_forever()
