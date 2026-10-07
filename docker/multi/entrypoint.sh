#!/bin/sh
# Without DHCPIF (netns sidecar): run the given command. Otherwise: veth + chilli.
set -e
[ -n "$DHCPIF" ] || exec "$@"
ip link show "$DHCPIF" >/dev/null 2>&1 || ip link add "$DHCPIF" type veth peer name "${DHCPIF}p"
ip link set "$DHCPIF" up
ip link set "${DHCPIF}p" up
sleep "${START_DELAY:-0}"   # STAGGER=<s> ./check.sh delays chilli-b (default 0: concurrent start)
exec chilli -c /etc/chilli/chilli.conf --fg --debug
