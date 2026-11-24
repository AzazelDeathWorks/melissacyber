probe() { printf '%-46s ' "$1"; curl -s -w ' [%{http_code}]\n' "$1" | head -c 250 | tr '\n' '|'; echo; }
B=http://127.0.0.1:8897
for q in widget alice bob carol sprocket gadget orders users a e i o u s 1 2; do probe "$B/search?q=$q"; done
probe "$B/orders/1001?id=1"
probe "$B/orders/1001?order=1"
probe "$B/debug?u=widget"
