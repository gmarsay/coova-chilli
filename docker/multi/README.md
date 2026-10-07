# Multi-instance chilli test (shared netns)

Runs several `chilli` containers in ONE network namespace (`netns` sidecar, like prod host networking)
with separate filesystems, then checks their iptables-legacy/ipset objects do not collide.

    cd docker/multi && ./check.sh          # build, run, assert, tear down; exit != 0 on FAIL
    STAGGER=8 ./check.sh                   # delay chilli-b by 8 s (default 0: concurrent start)

Instances start concurrently: `iptables-legacy -w` only serializes across containers if they share the
xtables lock, hence the `xtlock` volume + `XTABLES_LOCKFILE` env. Production must do the same.

Assertions: A0 each init OK, A1 one ipset per instance, A2 one FORWARD chain per instance,
B1-B3 after `stop chilli-a`, instance b's jump/chain/ipset survive, B4 instance a's objects are gone.
Failures print "CONFLICT DETECTED".

Add an instance `c`: create `instances/c/chilli.conf` (unique `radiusnasid`, `dhcpif vethc`,
`net`/`uamlisten` 10.3.0.x), then copy the `chilli-b` service in `docker-compose.yml` as `chilli-c`
with `DHCPIF: vethc` and its own conf mount. Services must be named `chilli-<x>` with `dhcpif veth<x>`.
