# chilli_dhcp(8)

## Name

`chilli_dhcp` — DHCP/IP-pool subprocess for CoovaChilli

## Synopsis

```
chilli_dhcp -b <binconfig>
```

## Description

`chilli_dhcp` is a dedicated subprocess launched automatically by `chilli`(8).
It owns all Layer-2 raw sockets, the DHCP state machine (`dhcp_t`), and the IP
address pool (`ippool_t`).  It runs its own `select()` event loop and
communicates with the main `chilli` process via a Unix `SOCK_DGRAM` socket.

`chilli_dhcp` is **always** started — there is no compile-time option to disable
it.  If it crashes, `chilli` detects the `SIGCHLD` and relaunches it
automatically, then resyncs authenticated session state via the IPC socket.

## Options

`chilli_dhcp` does **not** accept the full `chilli.conf` command-line syntax.
It loads its runtime configuration from a binary config file written by the
parent `chilli` process:

`-b <binconfig>`
:   Path to the binary configuration file (mandatory).  The parent writes this
    file with `chilli_binconfig(3)` before exec-ing the child.

## Architecture

```
  ┌──────────────────────────────┐
  │           chilli             │  main process
  │  app_conn_t sessions         │
  │  RADIUS client               │
  │  TUN interface (L3)          │
  │  nftables filtering          │
  │  IPC server  ←───────────────┼──┐
  └──────────────────────────────┘  │  Unix SOCK_DGRAM
                                    │
  ┌──────────────────────────────┐  │
  │         chilli_dhcp          │  │  subprocess
  │  raw L2 sockets              │  │
  │  dhcp_t  (DHCP state)        │  │
  │  ippool_t (IP pool)          │  │
  │  IPC client  ────────────────┼──┘
  └──────────────────────────────┘
```

### Responsibilities

| Concern | Owner |
|---------|-------|
| Raw Ethernet sockets | `chilli_dhcp` |
| DHCP state machine | `chilli_dhcp` |
| IP pool allocation / release | `chilli_dhcp` |
| app_conn_t session state | `chilli` |
| RADIUS authentication | `chilli` |
| TUN datapath (L3) | `chilli` |
| Packet filtering (allow/drop) | kernel nftables, set by `chilli` |

### IPC Protocol

Both processes exchange fixed-size `struct dhcpipc_msg` datagrams (see
`src/dhcpipc.h`).

| Message | Direction | Meaning |
|---------|-----------|---------|
| `DHCPIPC_NEW_CLIENT` | dhcp → main | New DHCP client; MAC + IP |
| `DHCPIPC_CLIENT_GONE` | dhcp → main | Client released / timed out |
| `DHCPIPC_SET_AUTHSTATE` | main → dhcp | Update `dhcp_conn_t.authstate` |
| `DHCPIPC_KICK_CLIENT` | main → dhcp | Force-release a client by MAC |

### IPC Socket Paths

By default:

| Socket | Path | Owned by |
|--------|------|----------|
| main server | `/var/run/chilli.dhcp` | `chilli` |
| dhcp server | `/var/run/chilli.dhcp.d` | `chilli_dhcp` |

The base path can be changed with `--dhcpsocket <path>` in `chilli.conf`.

### Packet Filtering (iptables-legacy + ipset)

`chilli` manages an ipset `chilli_authed` (type `hash:ip`, timeout 1 hour)
and two iptables-legacy rules in the `FORWARD` chain:

```
# Inserted at startup (via iptables-legacy -I FORWARD 1)
-i <dhcpif> -m set --match-set chilli_authed src -j ACCEPT
-o <dhcpif> -m set --match-set chilli_authed dst -j ACCEPT
```

When a session is authenticated, the client IP is added to `chilli_authed`;
on deauthentication or disconnect it is removed.  The set has a 1-hour
per-entry timeout as a safety net against missed removes.

Unauthenticated traffic is handled by the existing iptables policy (typically
a DROP or REDIRECT-to-captive-portal rule set up separately).

**System requirements**: `iptables-legacy` and `ipset` installed, `xt_set`
kernel module loaded.

## Files

`/var/run/chilli.dhcp`
:   Default IPC socket path (main side).

`/var/run/chilli.dhcp.d`
:   Default IPC socket path (chilli_dhcp side).

`/var/run/chilli-<pid>.conf`
:   Binary config file read at startup (written by parent `chilli`).

## See Also

chilli(8), chilli_query(1), chilli_opt(1)

## Authors

Based on CoovaChilli by David Bird (Coova Technologies).
chilli_dhcp architecture by Guillaume Marsay.
