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

- 16 GB of memory on every server, the control plane's and each scrubbing
  node's, or on one server running both. That is what Scrubline is sized for:
  at the most it is built to hold (a fabric of 128 nodes, and the largest
  policy and training set it takes), the control plane holds about 3 GB and a
  node agent under 300 MB, which leaves the rest to the OS and the datapath
  (README, [Sizing for a 16 GB server](../README.md#sizing-for-a-16-gb-server)).
  The script says so when a server has less, and installs anyway.
- Linux with systemd, and root: Debian 11 or later, Ubuntu 20.04 or later,
  RHEL 8 or later and its rebuilds (Rocky, Alma), Fedora, or openSUSE.
  Missing packages (`curl`, `iproute2`, or `iproute` and `iproute-tc` on the
  RHEL family, `nftables`, `openssl`) are installed with `apt-get`, `dnf` or
  `zypper` unless you pass `--no-deps`.
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
- The host firewall. When firewalld is running, as it is by default on the
  RHEL family, the script opens what Scrubline needs in it: GRE and IPIP on
  nodes, and the API's port on the control plane. Uninstalling closes what it
  opened. Any other firewall on the server must let in GRE and IPIP (IP
  protocols 47 and 4) from the other nodes and the customers' tunnel ends, and
  TCP to the API's port from the nodes and your panel. Scrubline's own tunnel
  firewall then narrows GRE and IPIP down to those addresses.

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
your panel calls the API with. `sudo /usr/local/bin/scrubline-ctl nodes` runs
`scrubctl` against the control plane with it.

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
tunnels it built. Until the control plane has a policy for the node there is
nothing to apply, and the provisioner leaves the box alone. The script
finishes by printing the node's id, which is what the panel pins tunnels to.

## Then

Deploy a policy, and pin each customer's tunnel to the node they should
connect to (`node` is the id from `GET /v1/nodes`). On the control plane's own
server the CA certificate is readable by root only; elsewhere, use the copy of
`ca.pem` you gave the nodes:

```sh
sudo curl --cacert /etc/scrubline/tls/ca.pem -X PUT -H "Authorization: Bearer $API_TOKEN" \
    https://10.0.0.5:8080/v1/tunnels/northwind \
    -d '{"remote":"198.18.0.9","tenant":"ten-…","rate_mbps":1000,"node":"node-…"}'
```

That node builds the customer's GRE tunnel from its tunnel IP and announces
their prefixes; the customer configures one tunnel, to that address. When it
passes 80% of its `--capacity-pps`, which it reports within a second of a flood
starting, or stops responding, the other nodes announce the prefixes too, scrub
what that attracts, and forward the clean traffic to it over node-to-node GRE.
`PUT /v1/tunnels/{id}/location` moves a customer to another node.
[docs/api.md](api.md#9-getting-the-clean-traffic-back) covers the API.

## The API at your own domain

The script serves the API over HTTPS with a certificate from its own private
CA. The nodes trust that certificate, but a browser or a hosted panel does
not. To give your panel an address like `https://api.example.com`, with a
certificate every client trusts, put [Caddy](https://caddyserver.com) in front
of the API. Caddy gets the certificate from Let's Encrypt and renews it, and
the nodes keep talking to the API directly.

1. Point a DNS name at the server with an `A` record, and let TCP 80 and 443
   in. Let's Encrypt checks the name over them.
2. On a single server, keep the API to the server itself, so Caddy is the
   only way in:

   ```sh
   sudo scripts/install.sh all --listen 127.0.0.1:8080
   ```

   With nodes on other servers, keep listening on every address instead, and
   let only the nodes' addresses reach the API's port.
3. [Install Caddy](https://caddyserver.com/docs/install), give it a copy of
   the CA certificate, and write `/etc/caddy/Caddyfile`:

   ```
   api.example.com {
   	# Nodes enrol with the API directly, never through here.
   	@register path /v1/nodes/register
   	respond @register 403
   	reverse_proxy https://127.0.0.1:8080 {
   		transport http {
   			tls_trusted_ca_certs /etc/caddy/scrubline-ca.pem
   		}
   	}
   }
   ```

   ```sh
   sudo install -m 0644 /etc/scrubline/tls/ca.pem /etc/caddy/scrubline-ca.pem
   sudo systemctl reload caddy
   curl https://api.example.com/health
   ```

Your panel then calls `https://api.example.com` with the operator token, as it
did before.

## A replica of the control plane

A replica follows the primary's state, serves reads, refuses writes, and can
take over. Install it on another server with the primary's tokens, from
`/etc/scrubline/api.env` there:

```sh
sudo scripts/install.sh api --replica-of https://10.0.0.5:8080 --ca primary-ca.pem \
    --api-token <primary's SCRUBLINE_API_TOKEN> --enroll-token <primary's SCRUBLINE_ENROLL_TOKEN>
```

It serves with a certificate from its own CA, unless you copy the primary's
`ca.pem` and `ca-key.pem` into `/etc/scrubline/tls/` on it first, in which case
its certificate comes from the primary's CA and everything that trusts the
primary trusts it too. To take over, promote it with `POST /v1/promote`, then
run `sudo scripts/install.sh api --primary` on it: a promoted replica that
restarts goes back to following otherwise.

## What it puts where

| Path | What |
| --- | --- |
| `/usr/local/bin/scrub-api`, `scrubctl`, `scrubline-ctl` | control plane, its CLI, and the CLI wired to this server |
| `/usr/local/bin/scrub-node`, `scrub-provision` | node agent and provisioner |
| `/etc/scrubline/api.env` | control-plane tokens and options |
| `/etc/scrubline/node.env` | node tokens and options |
| `/etc/scrubline/tls/` | the private CA and this server's certificate |
| `/etc/scrubline/api-ca.pem` | the CA of the control plane this server talks to, from `--ca` |
| `/etc/scrubline/install.conf` | the options you installed with, reused on the next run |
| `/var/lib/scrubline/state.json` | the control plane's durable state |
| `/run/scrubline-provision/status` | how the provisioner's last pass went |
| `/etc/systemd/system/scrubline-*.service` | the services |
| `/etc/sysctl.d/90-scrubline.conf` | forwarding on, reverse-path filtering loose (nodes) |
| `/etc/modules-load.d/scrubline.conf` | `ip_gre` and `ipip` at boot (nodes) |

The services run sandboxed: the control plane and the agent as the
unprivileged `scrubline` user, the provisioner as root with only
`CAP_NET_ADMIN`. The provisioner owns interfaces named `scr-*` (customer
tunnels) and `sbh-*` (node-to-node tunnels) and the `inet scrubline` nftables
table, and removes any of them it does not expect, so give your own
interfaces other names. It applies only commands of exactly the shapes the
agent renders, and loads the tunnel firewall before it brings up anything the
firewall filters; if the firewall does not load, it changes nothing else and
reports the node's tunnels down.

Reverse-path filtering is set loose because a customer's replies can come up
its tunnel for a prefix this node routes elsewhere. Turning IPv6 forwarding on
drops the default routes router advertisements gave, so an interface that
takes its IPv6 default route from them is set to keep accepting them first.

## Upgrading and changing settings

Run the same command again with `--pull` and no other options:

```sh
sudo scripts/install.sh node --pull
```

It pulls the checkout, then runs the installer the checkout now holds, so an
update is installed by its own installer. It rebuilds, reinstalls and restarts,
and keeps the tokens, the certificates and the options you gave before. Pass an
option to change it; whatever follows from it follows, such as the next hop
from `--tunnel-ip`, and on `all` the agent's API address from `--listen`. To
drop an option, so it goes back to its default, delete its line from
`/etc/scrubline/install.conf` and run the script again.

### From a private repository

A server pulls a private repository on GitHub with a deploy key: a key that
GitHub gives read-only access to that one repository. Set one up once on each
server:

```sh
sudo scripts/install.sh deploy-key
```

It makes the key in the checkout owner's `~/.ssh` (`scrubline-deploy`), and
prints it with where to add it: the repository's Settings > Deploy keys >
Add deploy key, with "Allow write access" left unticked. It points the
checkout's `origin` at GitHub over SSH with that key, and checks GitHub's SSH
host key against the fingerprint GitHub publishes before trusting it, since
what is pulled is built and installed as root. Once the key is added,
`--pull` needs no password. Run `deploy-key` again to check that GitHub
accepts it.

The server needs to reach github.com on TCP port 22, and the checkout is
pulled as whoever owns it.

A node's name and region are how the control plane knows it: changing either
enrols the server as a new node, and the tunnels pinned to the old one stay
with that one until you move them. The name and the tunnel IP are fixed the
first time the script works them out, so a new hostname or default route does
not move the node.

The script writes `api.env` and `node.env` whole on every run, keeping the
tokens and the `SCRUBLINE_*_EXTRA_OPTS` lines. Flags of the binaries that the
script has no option for go on those lines, and take precedence over the
script's own; restart the service after editing one.

Each service has a memory limit in its unit. The control plane is reclaimed
from past 8G and restarted at 10G; the agent past 1536M and at 2G, and it is
the last process on the server the kernel kills for memory; the provisioner is
held to 512M. Each is several times what the part holds at its bounds, so
reaching one is a fault rather than load. A limit of your own goes in a drop-in,
which the script leaves alone when it rewrites the units:

```sh
sudo systemctl edit scrubline-api      # [Service] then MemoryHigh=12G and MemoryMax=14G
```

The certificate it generated is reissued when its names change or it comes
within 30 days of expiring, so a re-run every couple of years renews it. The
private CA lasts ten years, and the script warns when it is about to run out.

Upgrade replicas before their primary, and agents before you assign tunnel
endpoints or pin tunnels: an older control plane drops state it does not know
about, and an older agent ignores what it was not built to read. Agents and the
control plane otherwise work across versions: an agent asks an older control
plane for its program every couple of seconds instead of waiting there for it,
and the control plane sheds for an older agent on its ten-second mean alone,
which takes seconds rather than one to see a flood.

## Seeing what it does

```sh
journalctl -u scrubline-node -u scrubline-provision -f
cat /run/scrubline-provision/status
sudo nft list table inet scrubline
ip -d link show type gre
```

To see what the provisioner would change without changing anything:

```sh
sudo sh -c 'export $(grep -E "^SCRUBLINE_NODE_API_TOKEN=" /etc/scrubline/node.env); /usr/local/bin/scrub-provision -once -dry-run'
```

## Removing it

```sh
sudo scripts/install.sh uninstall          # keeps credentials and state
sudo scripts/install.sh uninstall --purge  # removes those too
```

Uninstalling stops the services, removes the tunnels and firewall table the
provisioner built, and closes what the script opened in firewalld.
Forwarding settings stay as they are until the next boot.
