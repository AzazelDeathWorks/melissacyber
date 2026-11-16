#!/usr/bin/env python3
"""melissacyber demo lab: deliberately vulnerable web app (never expose it).
Mirrors the e2e test target: sqli, xss, ssrf, cmdi, ssti, lfi."""
import http.server, urllib.parse, time, urllib.request, threading

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _r(self, body, status=200):
        self.send_response(status); self.send_header("content-type","text/html")
        self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        g = lambda k: q.get(k,[""])[0]
        if u.path == "/search":
            s = g("q")
            if s.endswith("'") and "OR" not in s and "AND" not in s and "SLEEP" not in s:
                self._r("You have an error in your SQL syntax; check the manual")
            elif "SLEEP(3)" in s:
                time.sleep(3); self._r("results")
            elif "AND '1'='2" in s:
                self._r("no results")
            else:
                self._r("results for 1: row1 row2 row3")
        elif u.path == "/reflect":
            self._r(f"<html><body>search: {g('q')}</body></html>")
        elif u.path == "/exec":
            c = g("c")
            if "sleep 3" in c: time.sleep(3); self._r("done")
            elif "echo " in c: self._r(f"out: {c.split('echo ',1)[1]}")
            else: self._r("ok")
        elif u.path == "/tpl":
            n = g("name")
            if "{{" in n and "*" in n and "}}" in n: self._r("result: 475906")
            else: self._r(f"hello {n}")
        elif u.path == "/read":
            f = g("f")
            if "etc/passwd" in f: self._r("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon")
            else: self._r("not found", 404)
        elif u.path == "/fetch":
            if g("url"):
                threading.Thread(target=lambda: urllib.request.urlopen(g("url"),timeout=3),daemon=True).start()
            self._r("fetched")
        else:
            self._r("nope",404)

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv)>1 else 8899
    print(f"vulnerable lab on :{port}")
    http.server.HTTPServer(("127.0.0.1",port),H).serve_forever()
