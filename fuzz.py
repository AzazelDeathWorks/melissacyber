import urllib.request, urllib.parse, collections
B="http://127.0.0.1:8897/debug?u="
res=collections.Counter()
import random,string
cands=["1","'",'"',"`","%","_","*","..","\n","\t"," ","1' --","1'#","-1","0","%s","%d","{}","${1}","$(1)","1;","1' or 1=1--","admin'","'1'","\"1\"","1 and sleep(1)","1 AND 1=1-- -","\\","(",")","[","]","{","}","<",">","&","|","$","#","!","~","^","?","/","=","+",",",".","::","::1","1 2","A"*300,"A"*5000,"%0a","1%0a","1'%0a"]
for c in cands:
    u=B+urllib.parse.quote(c)
    try:
        r=urllib.request.urlopen(u,timeout=10); b=r.read().decode(); st=r.status
    except urllib.error.HTTPError as e:
        b=e.read().decode(); st=e.code
    key=(st,len(b),hash(b))
    res[key]+=1
    print(st,len(b),repr(c)[:40],hash(b))
print("distinct:",len(res))
