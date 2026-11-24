for u in "http://127.0.0.1:8897/.git/config" \
         "http://127.0.0.1:8897/.git/config?p=1" \
         "http://127.0.0.1:8897/.git/config?p=1%20AND%201=(WITH%20RECURSIVE%20c(x)%20AS%20(SELECT%201%20UNION%20ALL%20SELECT%20x+1%20FROM%20c%20WHERE%20x%3C100000000)%20SELECT%20max(x)%20FROM%20c)" \
         "http://127.0.0.1:8897/.git/head" \
         "http://127.0.0.1:8897/.git/index" \
         "http://127.0.0.1:8897/.git/refs/heads/main" \
         "http://127.0.0.1:8897/.git/logs/HEAD" \
         "http://127.0.0.1:8897/.git/config;p=1"; do
  echo "== $u"
  curl -s -o /tmp/o -w "%{http_code} %{size_download} %{time_total}\n" "$u"
  head -c 200 /tmp/o; echo
done
