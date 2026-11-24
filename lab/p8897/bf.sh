H='http://127.0.0.1:8897'
for p in "" "HEAD" "config" "description" "index" "COMMIT_EDITMSG" "FETCH_HEAD" "packed-refs" "info/refs" "info/exclude" "objects/info/packs" "logs/HEAD" "refs/heads/main" "refs/heads/master" "hooks" "config.orig" "config.bak" "config~" "srv.py" "app.py" ".gitignore" "robots.txt" "static/app.js"; do
  code=$(curl -s -o /tmp/o -w "%{http_code} %{size_download}" --path-as-is "$H/.git/$p")
  printf "%-24s => %s  %s\n" "/.git/$p" "$code" "$(head -c 60 /tmp/o | tr '\n' '|')"
done
