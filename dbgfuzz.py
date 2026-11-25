import requests, hashlib, itertools
base="http://127.0.0.1:8897"
keys=["id","q","search","url","name","user","file","exec","cmd","host","p","p1","n","num","sql","query","i","dbg","debug","trace","verbose","format","json","raw","output","show","echo","sel","table","col","where","limit","offset","order","sort","dir","page","start","ts","time","t","x","v","p2","a","b","param","params","args","data","input","term","keyword","k","s","p0","debugsql","conn"]
h0="124463bde7"
found=[]
for k in keys:
    for val in ("1","1'"):
        u=f"{base}/debug?{k}={requests.utils.quote(val)}"
        try:
            r=requests.get(u)
        except Exception as e:
            print("ERR",u,e); continue
        h=hashlib.md5(r.content).hexdigest()[:10]
        if h!=h0:
            print("DIFF", k, val, r.status_code, len(r.content), h, r.text[:200]); found.append(k)
# path variants
paths=["/debug/","/debug/sql","/debug/db","/debug?1","/debug?id","/debug?%27","/debug/1","/debug?id=1/","/debug/query?id=1","/debug/sql?id=1"]
for p in paths:
    r=requests.get(base+p)
    h=hashlib.md5(r.content).hexdigest()[:10]
    print(p, r.status_code, len(r.content), h, "" if h==h0 else "DIFF")
# method variants
for m in ("HEAD","POST","PUT","OPTIONS"):
    r=requests.request(m, base+"/debug?id=1'")
    print(m, r.status_code, len(r.content), r.headers)
