#!/bin/sh
# Starts N chilli in one shared netns and checks their ipset/iptables objects don't collide.
cd "$(dirname "$0")" || exit 2
SVCS=$(docker compose config --services | grep '^chilli-')
FAIL=0
ns() { docker compose exec -T netns sh -c "$1"; }
res() { if [ "$1" = 0 ]; then echo "PASS: $2"; else echo "FAIL: $2${3:+ -- $3}"; FAIL=1; fi; }
# Chain jumped to from FORWARD for interface $1, then the ipsets it matches.
fwd_chain() { ns "iptables-legacy -S FORWARD" | awk -v i="$1" '$3=="-i" && $4==i {print $6; exit}'; }
chain_sets() { ns "iptables-legacy -S $1 2>/dev/null" | awk '{for(k=1;k<NF;k++) if($k=="--match-set") print $(k+1)}' | sort -u; }
trap 'docker compose down -t 3 >/dev/null 2>&1' EXIT

docker compose down -t 3 >/dev/null 2>&1   # fresh netns = clean iptables/ipset
docker compose up -d --build || exit 2
for s in $SVCS; do
  t=0; until docker compose logs "$s" 2>&1 | grep -qE 'ipt_filter_init(: OK| failed)'; do
    t=$((t+2)); [ $t -ge 60 ] && { echo "TIMEOUT: $s never finished ipt_filter_init"; docker compose logs "$s" | tail -20; exit 2; }
    sleep 2; done
done

for s in $SVCS; do docker compose logs "$s" 2>&1 | grep -q 'ipt_filter_init: OK'
  res $? "A0 $s ipt_filter_init OK" "CONFLICT DETECTED: ipt_filter_init failed"; done
echo "== ipset list -n";            ns "ipset list -n"
echo "== FORWARD";                  ns "iptables-legacy -S FORWARD"
echo "== nat PREROUTING";           ns "iptables-legacy -t nat -S PREROUTING"
echo "== chains (filter / nat)";    ns "iptables-legacy -S | grep '^-N'; iptables-legacy -t nat -S | grep '^-N'"
echo "== ipt_filter errors in logs"; docker compose logs $SVCS 2>&1 | grep -E 'ipt_filter(_init)?[: \[]' | grep -vE 'rc=|: OK' || true

n=$(echo "$SVCS" | wc -l | tr -d ' ')
sets=$(ns "ipset list -n" | sort -u | wc -l | tr -d ' ')
[ "$sets" -ge "$n" ]; r=$?
res $r "A1 one ipset per instance ($sets sets for $n instances)" "CONFLICT DETECTED: instances share an ipset"
chains=$(for s in $SVCS; do fwd_chain "veth${s#chilli-}"; done | sort -u | wc -l | tr -d ' ')
[ "$chains" -ge "$n" ]; r=$?
res $r "A2 one FORWARD chain per instance ($chains chains for $n instances)" "CONFLICT DETECTED: instances share a chain"

docker compose stop chilli-a >/dev/null 2>&1; sleep 5
echo "== after stopping chilli-a"; ns "ipset list -n; iptables-legacy -S FORWARD; iptables-legacy -S | grep '^-N'"
c=$(fwd_chain vethb)
[ -n "$c" ]; res $? "B1 FORWARD still jumps for vethb" "CONFLICT DETECTED: jump removed by chilli-a"
[ -n "$c" ] && [ -n "$(ns "iptables-legacy -S $c 2>/dev/null" | grep -- '-A')" ]
res $? "B2 instance b chain '${c:-?}' still has rules" "CONFLICT DETECTED: flushed/deleted by chilli-a"
st=$([ -n "$c" ] && chain_sets "$c" | head -1)
[ -n "$st" ] && ns "ipset list -n" | grep -qx "$st"
res $? "B3 instance b ipset '${st:-?}' still exists" "CONFLICT DETECTED: set gone (destroyed by chilli-a, or chain flushed)"
left=$(ns "ipset list -n; iptables-legacy -S; iptables-legacy -t nat -S" | grep -E 'vetha|_hs_a$|_hs_a ' || true)
[ -z "$left" ]; res $? "B4 instance a objects removed at shutdown" "ipt_filter_cleanup left: $(echo "$left" | tr '\n' ';')"

[ $FAIL = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit $FAIL
