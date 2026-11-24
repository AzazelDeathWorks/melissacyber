H='http://127.0.0.1:8897'
for r in "/" "/search" "/item" "/user" "/files" "/faq" "/echo" "/debug" "/token" "/api/user" "/orders/1001" "/orders/1001/items" "/fetch" "/robots.txt" "/static/app.js" "/.git/config" "/api/me" "/api/user/1" "/items" "/users"; do
  a=$(curl -s "$H$r")
  b=$(curl -s "$H$r?p=MARK9")
  if [ "$a" != "$b" ]; then echo "DIFF $r :: base=[$a] p=[$b]"; else echo "same $r"; fi
done
