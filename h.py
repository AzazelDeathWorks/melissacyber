import urllib.request
def g(hdr,url="http://127.0.0.1:8897/debug?u=1"):
    r=urllib.request.Request(url,headers=hdr)
    try:
        x=urllib.request.urlopen(r,timeout=10); print(x.status,x.read().decode()[:200],"|",hdr)
    except urllib.error.HTTPError as e: print(e.code,e.read().decode()[:150],"|",hdr)
g({"Host":"localhost"})
g({"User-Agent":"sqlmap/1.7"})
g({"X-Forwarded-For":"127.0.0.1"})
g({"Accept":"application/json"})
g({"Referer":"http://127.0.0.1:8897/debug"})
g({},"http://localhost:8897/debug?u=1")
g({"Cookie":"debug=1"})
