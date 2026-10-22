# Installing on servers

[`scripts/install.sh`](../scripts/install.sh) installs Scrubline as systemd
services on Linux: the control plane on one server, and a scrubbing node on
each server that scrubs traffic. Every node it installs pulls its
configuration from the control plane and puts it on the box: the customers'
GRE tunnels, the node-to-node tunnels, the routes, the tunnel firewall and the
clean-traffic shapers. A server added later picks all of that up when it
enrols, and every other server accepts its tunnels on the next compile.

| Role | Runs | For |
| --- | --- | --- |
| `api` | `scrubline-api` | the control plane your panel talks to |
| `node` | `scrubline-node`, `scrubline-provision` | a scrubbing node: the agent, and the provisioner that applies its tunnels |
| `all` | all three | trying it, or a single-server fabric |

## Before you start

- Linux with systemd, and root. Debian, Ubuntu, RHEL and their relatives work;
  missing packages (`curl`, `iproute2`, `nftables`, `openssl`) are installed
  with the system's package manager unless you pass `--no-deps`.
- A checkout of this repository on each server, and a Rust toolchain to build
  it (<https://rustup.rs>). The script builds as the user who ran `sudo`, so
  `target/` stays theirs. To build once and copy the result instead, run
  `make build` on a build machine and pass `--bin-dir bin` on the servers.
- On scrubbing nodes, a kernel with GRE and IPIP (`ip_gre`, `ipip`); every
  distribution kernel has them.
- Each scrubbing node's **tunnel IP**: an IPv4 address the server already has
  and that is routed to it. Customers' GRE tunnels end on it, and so do the
  other nodes' tunnels. The script uses the source address of the default route
  unless you pass `--tunnel-ip`; Scrubline never configures the address itself.

## Install the control plane

```sh
git clone <this repository> scrubline && cd scrubline
sudo scripts/install.sh api --hostname scrub.example.com
```

It builds the binaries, creates a private CA and a certificate for this
server, generates the operator and enrollment tokens, and starts the API on
`0.0.0.0:8080` over TLS. `--hostname` adds a name or address to the
certificate, such as a public address the nodes reach this server on; the
server's own hostname and addresses are always in it. Bring your own
certificate with `--tls-cert` and `--tls-key` instead.

It finishes by printing the command to install a node, enrollment token
included:

```
To add a scrubbing node, copy /etc/scrubline/tls/ca.pem to it and run there:
  sudo scripts/install.sh node --api https://10.0.0.5:8080 \
      --ca /path/to/ca.pem --enroll-token 3f2a…9c \
      --name <name> --region <location>
```

The operator token, `SCRUBLINE_API_TOKEN` in `/etc/scrubline/api.env`, is what
your panel calls the API with. `sudo scrubline-ctl nodes` runs `scrubctl`
against the control plane with it.

## Install each scrubbing node

Copy the CA certificate across, then:

```sh
sudo scripts/install.sh node --api https://10.0.0.5:8080 --ca ca.pem \
    --enroll-token 3f2a…9c --name lhr-1 --region lhr \
    --capacity-pps 2000000 --local-as 64512
```

| Option | Default | |
| --- | --- | --- |
| `--name` | hostname | how the node shows up in the API and the panel |
| `--region` | `default` | its location, for steering and for your panel |
| `--tunnel-ip` | source of the default route | its own IPv4 address for tunnels |
| `--capacity` | `10` | Gbit/s, for weighting announcements |
| `--capacity-pps` | `1000000` | packets per second it takes before the fabric helps it with the customers pinned to it |
| `--local-as` | none | the AS it announces from; announcements need one |
| `--bgp-next-hop` | the tunnel IP | next hop in its announcements |
| `--no-provision` | | install the agent only, and apply its configuration with your own tooling |

The node enrols with the control plane, which issues it its own credential.
The agent listens on `127.0.0.1:9091` only; the provisioner beside it applies
what the agent serves every few seconds and reports back which customer
tunnels it built.

## Then

Deploy a policy, and pin each customer's tunnel to the node they should
connect to (`node` is the id from `GET /v1/nodes`):

```sh
curl -X PUT -H "Authorization: Bearer $API_TOKEN" https://10.0.0.5:8080/v1/tunnels/northwind \
    -d '{"remote":"198.18.0.9","tenant":"ten-…","rate_mbps":1000,"node":"node-…"}'
```

That node builds the customer's GRE tunnel from its tunnel IP and announces
their prefixes; the customer configures one tunnel, to that address. When it
passes 80% of its `--capacity-pps`, or stops responding, the other nodes
announce the prefixes too, scrub what that attracts, and forward the clean
traffic to it over node-to-node GRE. `PUT /v1/tunnels/{id}/location` moves a
customer to another node. [docs/api.md](api.md#9-getting-the-clean-traffic-back)
covers the API.

## What it puts where

| Path | What |
| --- | --- |
| `/usr/local/bin/scrub-api`, `scrubctl`, `scrubline-ctl` | control plane, its CLI, and the CLI wired to this server |
| `/usr/local/bin/scrub-node`, `scrub-provision` | node agent and provisioner |
| `/etc/scrubline/api.env` | control-plane tokens and options |
| `/etc/scrubline/node.env` | node tokens and options |
| `/etc/scrubline/tls/` | the private CA and this server's certificate |
| `/etc/scrubline/install.conf` | the options you installed with, reused on the next run |
| `/var/lib/scrubline/state.json` | the control plane's durable state |
| `/etc/systemd/system/scrubline-*.service` | the services |
| `/etc/sysctl.d/90-scrubline.conf` | forwarding on, reverse-path filtering loose (nodes) |
| `/etc/modules-load.d/scrubline.conf` | `ip_gre` and `ipip` at boot (nodes) |

The services run sandboxed: the control plane and the agent as the
unprivileged `scrubline` user, the provisioner as root with only
`CAP_NET_ADMIN`. The provisioner owns interfaces named `scr-*` (customer
tunnels) and `sbh-*` (node-to-node tunnels) and the `inet scrubline` nftables
table, and removes any of them it does not expect, so give your own
interfaces other names.

Reverse-path filtering is set loose because a customer's replies can come up
its tunnel for a prefix this node routes elsewhere. IPv6 forwarding turns off
router advertisements, so an interface that takes its IPv6 default route from
them is set to keep accepting them.

## Upgrading and changing settings

Pull and run the same command again, without options:

```sh
git pull && sudo scripts/install.sh node
```

It rebuilds, reinstalls and restarts, and keeps the tokens, the certificates
and the options from the last run. Pass an option to change it. The
certificate it generated is reissued when its names change or it comes within
30 days of expiring, so a re-run every couple of years renews it.

Upgrade replicas before their primary, and agents before you assign tunnel
endpoints or pin tunnels: an older control plane drops state it does not know
about, and an older agent ignores what it was not built to read.

## Seeing what it does

```sh
journalctl -u scrubline-node -u scrubline-provision -f
sudo nft list table inet scrubline
ip -d link show type gre
```

To see what the provisioner would change without changing anything:

```sh
sudo sh -c 'export $(grep -E "^SCRUBLINE_NODE_API_TOKEN=" /etc/scrubline/node.env); scrub-provision -once -dry-run'
```

## Removing it

```sh
sudo scripts/install.sh uninstall          # keeps credentials and state
sudo scripts/install.sh uninstall --purge  # removes those too
```

Uninstalling stops the services and removes the tunnels and firewall table
the provisioner built. Forwarding settings stay as they are until the next
boot.
