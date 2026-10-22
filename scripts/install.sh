#!/usr/bin/env bash
# Installs Scrubline on a Linux server running systemd.
#
#   sudo scripts/install.sh api        the control plane
#   sudo scripts/install.sh node       a scrubbing node: the agent, and the provisioner that puts
#                                      its tunnels, routes, firewall and shapers onto the box
#   sudo scripts/install.sh all        both, on one server
#   sudo scripts/install.sh uninstall  remove the services (add --purge to remove state too)
#
# Run it again to upgrade: it rebuilds or recopies the binaries, rewrites the services and
# restarts them, and keeps the credentials, certificates and settings from the first run.
# scripts/install.sh --help lists every option; docs/install.md walks through a fabric.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=/usr/local/bin
ETC=/etc/scrubline
STATE=/var/lib/scrubline
UNITS=/etc/systemd/system
SETTINGS=$ETC/install.conf

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'USAGE'
Usage: sudo scripts/install.sh <api|node|all|uninstall> [options]

Control plane (api, all):
  --listen ADDR           address the API serves on (default 0.0.0.0:8080)
  --tls-cert FILE         certificate to serve with, with --tls-key; without them a private
  --tls-key FILE          CA and a certificate for this server are generated
  --hostname NAME         another name or address to put in the generated certificate, such as
                          a public address the nodes reach this server on (repeatable)

Scrubbing node (node, all):
  --api URL               the control plane, e.g. https://10.0.0.5:8080 (all: this server)
  --enroll-token TOKEN    the control plane's enrollment token (all: read from this server)
  --ca FILE               the CA certificate that signed the control plane's certificate, for a
                          private CA such as the one the api install generates
  --name NAME             this node's name (default: the hostname)
  --region REGION         where it is, e.g. lhr or fra (default: default)
  --tunnel-ip IP          this server's own IPv4 address, which customers' GRE tunnels and the
                          other nodes' tunnels end on (default: the source of the default route)
  --capacity GBPS         bandwidth it scrubs, in Gbit/s, for weighting (default 10)
  --capacity-pps PPS      packets per second it takes before the fabric helps it with the
                          customers pinned to it (default 1000000)
  --local-as ASN          the AS it announces from
  --bgp-next-hop IP       next hop in its announcements (default: the tunnel IP)
  --no-provision          do not install the provisioner; apply the agent's config yourself
  --provision             install it again after --no-provision

Either:
  --bin-dir DIR           install the binaries from DIR instead of building them
  --no-deps               do not install missing packages
  --no-start              configure everything but do not start or restart anything
  --purge                 with uninstall: also remove credentials, certificates and state
USAGE
}

[[ $# -gt 0 ]] || {
	usage
	exit 1
}
ROLE=$1
shift
case $ROLE in
api | node | all | uninstall) ;;
-h | --help | help)
	usage
	exit 0
	;;
*) die "unknown role '$ROLE'; use api, node, all or uninstall" ;;
esac
[[ $(id -u) -eq 0 ]] || die "run this as root (sudo scripts/install.sh $ROLE ...)"

# Settings from an earlier run are the defaults, so an upgrade needs no options repeated.
LISTEN='' TLS_CERT='' TLS_KEY='' HOSTNAMES='' API_URL='' ENROLL_TOKEN='' CA='' NAME=''
REGION='' TUNNEL_IP='' CAPACITY='' CAPACITY_PPS='' LOCAL_AS='' NEXT_HOP='' PROVISION=''
CUSTOM_TLS=''
if [[ -f $SETTINGS ]]; then
	# shellcheck source=/dev/null
	. "$SETTINGS"
fi
BIN_DIR='' DEPS=1 START=1 PURGE=0
EXTRA_HOSTS=()
need() { [[ $# -ge 2 && -n $2 ]] || die "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
	case $1 in
	--listen) need "$@"; LISTEN=$2; shift ;;
	--tls-cert) need "$@"; TLS_CERT=$2; shift ;;
	--tls-key) need "$@"; TLS_KEY=$2; shift ;;
	--hostname) need "$@"; EXTRA_HOSTS+=("$2"); shift ;;
	--api) need "$@"; API_URL=$2; shift ;;
	--enroll-token) need "$@"; ENROLL_TOKEN=$2; shift ;;
	--ca) need "$@"; CA=$2; shift ;;
	--name) need "$@"; NAME=$2; shift ;;
	--region) need "$@"; REGION=$2; shift ;;
	--tunnel-ip) need "$@"; TUNNEL_IP=$2; shift ;;
	--capacity) need "$@"; CAPACITY=$2; shift ;;
	--capacity-pps) need "$@"; CAPACITY_PPS=$2; shift ;;
	--local-as) need "$@"; LOCAL_AS=$2; shift ;;
	--bgp-next-hop) need "$@"; NEXT_HOP=$2; shift ;;
	--no-provision) PROVISION=0 ;;
	--provision) PROVISION=1 ;;
	--bin-dir) need "$@"; BIN_DIR=$2; shift ;;
	--no-deps) DEPS=0 ;;
	--no-start) START=0 ;;
	--purge) PURGE=1 ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown option $1 (see --help)" ;;
	esac
	shift
done
# Extra certificate names accumulate across runs, once each.
for h in "${EXTRA_HOSTS[@]}"; do
	case ",$HOSTNAMES," in
	*",$h,"*) ;;
	*) HOSTNAMES="${HOSTNAMES:+$HOSTNAMES,}$h" ;;
	esac
done

SYSTEMD=0
if [[ -d /run/systemd/system ]]; then SYSTEMD=1; fi
has_api() { [[ $ROLE == api || $ROLE == all ]]; }
has_node() { [[ $ROLE == node || $ROLE == all ]]; }

# Options reach the binaries through systemd, which splits them on whitespace.
plain() {
	local bad='[[:space:]"'\''\\$]'
	[[ -n $2 && ! $2 =~ $bad ]] || die "$1 must be a single word, without quotes or \$: '$2'"
}
ipv4() {
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	local p
	for p in "${BASH_REMATCH[@]:1}"; do
		((10#$p <= 255)) || return 1
	done
}
# This server's global addresses.
addresses() { ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
token() { head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n'; }
# The value of KEY in an env file this script wrote, if it is there.
read_env() {
	if [[ -f $1 ]]; then
		sed -n "s/^$2=//p" "$1" | head -n1
	fi
}

uninstall() {
	if [[ $SYSTEMD -eq 1 ]]; then
		for unit in scrubline-provision scrubline-node scrubline-api; do
			systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
		done
	fi
	rm -f "$UNITS"/scrubline-{api,node,provision}.service "$PREFIX/scrubline-ctl"
	if [[ $SYSTEMD -eq 1 ]]; then
		systemctl daemon-reload
	fi
	# The provisioner's tunnels and rules go with it.
	if command -v ip >/dev/null; then
		for link in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(scr|sbh)-' || true); do
			ip link del "$link" 2>/dev/null || true
		done
	fi
	if command -v nft >/dev/null; then
		nft delete table inet scrubline 2>/dev/null || true
	fi
	rm -f "$PREFIX"/{scrub-api,scrub-node,scrub-provision,scrubctl}
	rm -f /etc/modules-load.d/scrubline.conf /etc/sysctl.d/90-scrubline.conf
	if [[ $PURGE -eq 1 ]]; then
		rm -rf "$ETC" "$STATE"
		if id scrubline >/dev/null 2>&1; then
			userdel scrubline 2>/dev/null || true
		fi
		say "removed Scrubline, its credentials, certificates and state"
	else
		say "removed Scrubline; credentials and state are kept in $ETC and $STATE (--purge removes them)"
	fi
	say "forwarding and reverse-path settings stay as they are until the next boot"
}
if [[ $ROLE == uninstall ]]; then
	uninstall
	exit 0
fi

# ---------------------------------------------------------------- settings
LISTEN=${LISTEN:-0.0.0.0:8080}
PORT=${LISTEN##*:}
[[ $PORT =~ ^[0-9]+$ ]] || die "--listen needs a port, e.g. 0.0.0.0:8080"
plain --listen "$LISTEN"
if [[ -n $TLS_CERT || -n $TLS_KEY ]]; then
	[[ -n $TLS_CERT && -n $TLS_KEY ]] || die "--tls-cert and --tls-key go together"
	[[ -f $TLS_CERT && -f $TLS_KEY ]] || die "--tls-cert and --tls-key must be files"
fi
PROVISION=${PROVISION:-1}
if has_node; then
	NAME=${NAME:-$(hostname -s)}
	REGION=${REGION:-default}
	CAPACITY=${CAPACITY:-10}
	CAPACITY_PPS=${CAPACITY_PPS:-1000000}
	plain --name "$NAME"
	[[ $NAME != *[/\|]* ]] || die "--name must not contain '/' or '|'"
	plain --region "$REGION"
	[[ $CAPACITY =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--capacity must be a number of Gbit/s"
	[[ $CAPACITY_PPS =~ ^[0-9]+$ ]] || die "--capacity-pps must be a whole number"
	[[ -z $LOCAL_AS || $LOCAL_AS =~ ^[0-9]+$ ]] || die "--local-as must be an AS number"
	if [[ -z $TUNNEL_IP ]]; then
		TUNNEL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
		[[ -n $TUNNEL_IP ]] || die "could not work out this server's IPv4 address; pass --tunnel-ip"
	fi
	ipv4 "$TUNNEL_IP" || die "--tunnel-ip must be an IPv4 address: '$TUNNEL_IP'"
	NEXT_HOP=${NEXT_HOP:-$TUNNEL_IP}
	plain --bgp-next-hop "$NEXT_HOP"
	if [[ $ROLE == all ]]; then
		API_URL=${API_URL:-https://127.0.0.1:$PORT}
	fi
	[[ -n $API_URL ]] || die "--api is required: the control plane's URL, e.g. https://10.0.0.5:8080"
	plain --api "$API_URL"
	[[ $API_URL == https://* || $API_URL == http://127.* || $API_URL == http://localhost* ]] ||
		die "--api must be https:// (only a control plane on this server may be reached in the clear)"
fi

# ---------------------------------------------------------------- packages
pm_install() {
	if command -v apt-get >/dev/null; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null 2>&1 ||
			{ apt-get update -q >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null 2>&1; }
	elif command -v dnf >/dev/null; then
		dnf install -y -q "$@" >/dev/null
	elif command -v yum >/dev/null; then
		yum install -y -q "$@" >/dev/null
	elif command -v zypper >/dev/null; then
		zypper --non-interactive install "$@" >/dev/null
	else
		return 1
	fi
}
missing=()
command -v curl >/dev/null || missing+=(curl ca-certificates)
command -v ip >/dev/null || missing+=(iproute2)
if has_api; then
	command -v openssl >/dev/null || missing+=(openssl)
fi
if has_node; then
	command -v tc >/dev/null || missing+=(iproute2)
	command -v nft >/dev/null || missing+=(nftables)
fi
if [[ ${#missing[@]} -gt 0 ]]; then
	[[ $DEPS -eq 1 ]] || die "missing ${missing[*]} (and --no-deps was given)"
	say "installing ${missing[*]}"
	# RHEL-family systems package ip and tc as iproute, not iproute2.
	pm_install "${missing[@]}" || pm_install "${missing[@]/iproute2/iproute}" ||
		die "could not install ${missing[*]}; install them and run this again"
fi

# ---------------------------------------------------------------- binaries
BINS=()
if has_api; then BINS+=(scrub-api scrubctl); fi
if has_node; then BINS+=(scrub-node); fi
if has_node && [[ $PROVISION == 1 ]]; then BINS+=(scrub-provision); fi

# How to run cargo: as whoever ran sudo when they have it, so target/ stays theirs and their
# toolchain is the one used, or else as root.
BUILDER=()
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
	builder_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	if sudo -u "$SUDO_USER" -H env "PATH=$builder_home/.cargo/bin:$PATH" sh -c 'command -v cargo' >/dev/null 2>&1; then
		BUILDER=(sudo -u "$SUDO_USER" -H env "PATH=$builder_home/.cargo/bin:$PATH")
	fi
fi
if [[ ${#BUILDER[@]} -eq 0 ]] && env "PATH=$HOME/.cargo/bin:$PATH" sh -c 'command -v cargo' >/dev/null 2>&1; then
	BUILDER=(env "PATH=$HOME/.cargo/bin:$PATH")
fi
if [[ -z $BIN_DIR ]]; then
	if [[ -f $REPO/Cargo.toml && ${#BUILDER[@]} -gt 0 ]]; then
		say "building the binaries (cargo build --release; the first build takes a few minutes)"
		(cd "$REPO" && "${BUILDER[@]}" cargo build --locked --release --bins) || die "the build failed"
		BIN_DIR=$REPO/target/release
	elif [[ -x $REPO/bin/${BINS[0]} ]]; then
		BIN_DIR=$REPO/bin
		warn "no Rust toolchain found; installing the prebuilt binaries in $BIN_DIR"
	else
		die "no Rust toolchain to build with. Install one (https://rustup.rs), or build elsewhere with 'make build' and pass --bin-dir"
	fi
fi
for b in "${BINS[@]}"; do
	[[ -x $BIN_DIR/$b ]] || die "$BIN_DIR/$b is missing"
done
say "installing ${BINS[*]} into $PREFIX"
for b in "${BINS[@]}"; do
	install -m 0755 "$BIN_DIR/$b" "$PREFIX/$b.new"
	mv -f "$PREFIX/$b.new" "$PREFIX/$b"
done

# ---------------------------------------------------------------- account and directories
if ! id scrubline >/dev/null 2>&1; then
	useradd --system --home-dir "$STATE" --no-create-home \
		--shell "$(command -v nologin || echo /usr/sbin/nologin)" scrubline
fi
install -d -m 0750 -o root -g scrubline "$ETC"
install -d -m 0750 -o scrubline -g scrubline "$STATE"
umask 077

# ---------------------------------------------------------------- control plane
# A private CA and a certificate for this server, reissued when its names change or it comes
# within 30 days of expiring. The CA's key stays root's; only the server key is readable by the
# service.
certificates() {
	local tls=$ETC/tls
	install -d -m 0750 -o root -g scrubline "$tls"
	if [[ -n $TLS_CERT ]]; then
		install -m 0644 "$TLS_CERT" "$tls/server.pem"
		install -m 0640 -g scrubline "$TLS_KEY" "$tls/server-key.pem"
		CUSTOM_TLS=1
		return
	fi
	if [[ $CUSTOM_TLS == 1 && -f $tls/server.pem ]]; then
		return
	fi
	CUSTOM_TLS=0
	if [[ ! -f $tls/ca.pem || ! -f $tls/ca-key.pem ]]; then
		say "creating a private CA in $tls"
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-keyout "$tls/ca-key.pem" -out "$tls/ca.pem" -days 3650 \
			-subj "/CN=Scrubline CA $(hostname -s)" \
			-addext basicConstraints=critical,CA:TRUE \
			-addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
		chmod 0600 "$tls/ca-key.pem"
		chmod 0644 "$tls/ca.pem"
		rm -f "$tls/server.pem"
	fi
	local sans fqdn addr h
	sans="DNS:localhost,IP:127.0.0.1,DNS:$(hostname -s)"
	fqdn=$(hostname -f 2>/dev/null || true)
	if [[ -n $fqdn && $fqdn != "$(hostname -s)" ]]; then
		sans+=",DNS:$fqdn"
	fi
	for addr in $(addresses); do
		sans+=",IP:$addr"
	done
	local -a extra=()
	IFS=, read -r -a extra <<<"$HOSTNAMES"
	for h in "${extra[@]}"; do
		[[ -n $h ]] || continue
		if ipv4 "$h" || [[ $h == *:* ]]; then sans+=",IP:$h"; else sans+=",DNS:$h"; fi
	done
	if [[ -f $tls/server.pem && "$(cat "$tls/server.sans" 2>/dev/null)" == "$sans" ]] &&
		openssl x509 -checkend 2592000 -noout -in "$tls/server.pem" >/dev/null; then
		return
	fi
	say "issuing a certificate for this server ($sans)"
	local scratch
	scratch=$(mktemp -d)
	printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$sans" >"$scratch/ext"
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout "$scratch/key.pem" -out "$scratch/req.csr" -subj "/CN=$(hostname -s)" 2>/dev/null
	openssl x509 -req -in "$scratch/req.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca-key.pem" \
		-CAcreateserial -CAserial "$tls/ca.srl" -out "$scratch/cert.pem" -days 825 \
		-extfile "$scratch/ext" 2>/dev/null
	install -m 0644 "$scratch/cert.pem" "$tls/server.pem"
	install -m 0640 -g scrubline "$scratch/key.pem" "$tls/server-key.pem"
	printf '%s' "$sans" >"$tls/server.sans"
	rm -rf "$scratch"
}

if has_api; then
	certificates
	api_token=$(read_env "$ETC/api.env" SCRUBLINE_API_TOKEN)
	enroll_token=$(read_env "$ETC/api.env" SCRUBLINE_ENROLL_TOKEN)
	api_token=${api_token:-$(token)}
	enroll_token=${enroll_token:-$(token)}
	cat >"$ETC/api.env.new" <<ENV
# Written by scripts/install.sh. To change an option, edit SCRUBLINE_API_OPTS and run
# systemctl restart scrubline-api. The tokens are secrets: the operator token can change
# everything, and every node holds the enrollment token.
SCRUBLINE_API_TOKEN=$api_token
SCRUBLINE_ENROLL_TOKEN=$enroll_token
SCRUBLINE_API_OPTS=-addr $LISTEN -state $STATE/state.json -tls-cert $ETC/tls/server.pem -tls-key $ETC/tls/server-key.pem
ENV
	install -m 0640 -o root -g scrubline "$ETC/api.env.new" "$ETC/api.env"
	rm -f "$ETC/api.env.new"
	rm -f "$PREFIX/scrubline-ctl"
	if [[ $CUSTOM_TLS != 1 ]]; then
		# scrubctl against this control plane with its operator token: sudo scrubline-ctl nodes
		cat >"$PREFIX/scrubline-ctl.new" <<CTL
#!/bin/sh
# scrubctl against this server's control plane, with its operator token. Written by
# scripts/install.sh.
set -e
SCRUBLINE_API_TOKEN=\$(sed -n 's/^SCRUBLINE_API_TOKEN=//p' $ETC/api.env)
export SCRUBLINE_API_TOKEN
exec $PREFIX/scrubctl -api https://127.0.0.1:$PORT -ca $ETC/tls/ca.pem "\$@"
CTL
		install -m 0750 "$PREFIX/scrubline-ctl.new" "$PREFIX/scrubline-ctl"
		rm -f "$PREFIX/scrubline-ctl.new"
	fi
fi

# ---------------------------------------------------------------- scrubbing node
if has_node; then
	if [[ $ROLE == all ]]; then
		ENROLL_TOKEN=$enroll_token
		if [[ -z $CA && $CUSTOM_TLS != 1 ]]; then
			CA=$ETC/tls/ca.pem
		fi
	fi
	ENROLL_TOKEN=${ENROLL_TOKEN:-$(read_env "$ETC/node.env" SCRUBLINE_ENROLL_TOKEN)}
	[[ -n $ENROLL_TOKEN ]] || die "--enroll-token is required: SCRUBLINE_ENROLL_TOKEN from the control plane's $ETC/api.env"
	plain --enroll-token "$ENROLL_TOKEN"
	if [[ -n $CA && $CA != "$ETC"/* ]]; then
		[[ -f $CA ]] || die "--ca $CA does not exist"
		install -m 0644 "$CA" "$ETC/api-ca.pem"
		CA=$ETC/api-ca.pem
	fi
	node_token=$(read_env "$ETC/node.env" SCRUBLINE_NODE_API_TOKEN)
	node_token=${node_token:-$(token)}
	opts="-api $API_URL -name $NAME -region $REGION -capacity $CAPACITY -capacity-pps $CAPACITY_PPS"
	opts+=" -listen 127.0.0.1:9091 -advertise $TUNNEL_IP:9091 -tunnel-src $TUNNEL_IP -bgp-next-hop $NEXT_HOP"
	if [[ -n $LOCAL_AS ]]; then
		opts+=" -local-as $LOCAL_AS"
	fi
	if [[ -n $CA ]]; then
		opts+=" -ca $CA"
	fi
	cat >"$ETC/node.env.new" <<ENV
# Written by scripts/install.sh. To change an option, edit it below and run
# systemctl restart scrubline-node scrubline-provision.
SCRUBLINE_ENROLL_TOKEN=$ENROLL_TOKEN
SCRUBLINE_NODE_API_TOKEN=$node_token
SCRUBLINE_NODE_OPTS=$opts
SCRUBLINE_PROVISION_OPTS=-agent http://127.0.0.1:9091
ENV
	install -m 0640 -o root -g scrubline "$ETC/node.env.new" "$ETC/node.env"
	rm -f "$ETC/node.env.new"

	# The kernel side of tunnels: GRE and IPIP, forwarding, and reverse-path filtering loose
	# enough for a customer's replies to come up a tunnel for a prefix this node routes elsewhere.
	printf 'ip_gre\nipip\n' >/etc/modules-load.d/scrubline.conf
	chmod 0644 /etc/modules-load.d/scrubline.conf
	if ! { modprobe ip_gre && modprobe ipip; } 2>/dev/null; then
		warn "could not load the ip_gre and ipip modules now; they load at the next boot"
	fi
	{
		printf '%s\n' "# Written by scripts/install.sh for a Scrubline scrubbing node." \
			"net.ipv4.ip_forward = 1" \
			"net.ipv6.conf.all.forwarding = 1" \
			"net.ipv4.conf.all.rp_filter = 2" \
			"net.ipv4.conf.default.rp_filter = 2"
		# Forwarding turns off router advertisements, so an interface that takes its IPv6
		# default route from them keeps accepting them.
		for dev in $(ip -6 route show default proto ra 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | sort -u); do
			printf 'net/ipv6/conf/%s/accept_ra = 2\n' "$dev"
		done
	} >/etc/sysctl.d/90-scrubline.conf
	chmod 0644 /etc/sysctl.d/90-scrubline.conf
	if ! sysctl -q -p /etc/sysctl.d/90-scrubline.conf >/dev/null 2>&1; then
		warn "could not apply /etc/sysctl.d/90-scrubline.conf now; it applies at the next boot"
	fi
fi

# ---------------------------------------------------------------- services
# Written whole each run, so an upgrade picks up changes to them.
HARDENING='NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native'
umask 022
if has_api; then
	cat >"$UNITS/scrubline-api.service" <<UNIT
[Unit]
Description=Scrubline control plane
Documentation=file://$REPO/docs/install.md
After=network-online.target
Wants=network-online.target

[Service]
User=scrubline
Group=scrubline
EnvironmentFile=$ETC/api.env
ExecStart=$PREFIX/scrub-api \$SCRUBLINE_API_OPTS
Restart=on-failure
RestartSec=2
StateDirectory=scrubline
StateDirectoryMode=0750
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryDenyWriteExecute=yes
$HARDENING

[Install]
WantedBy=multi-user.target
UNIT
fi
if has_node; then
	after=network-online.target
	if [[ $ROLE == all ]]; then after+=" scrubline-api.service"; fi
	cat >"$UNITS/scrubline-node.service" <<UNIT
[Unit]
Description=Scrubline scrubbing node agent
Documentation=file://$REPO/docs/install.md
After=$after
Wants=network-online.target

[Service]
User=scrubline
Group=scrubline
EnvironmentFile=$ETC/node.env
ExecStart=$PREFIX/scrub-node \$SCRUBLINE_NODE_OPTS
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryDenyWriteExecute=yes
$HARDENING

[Install]
WantedBy=multi-user.target
UNIT
	if [[ $PROVISION == 1 ]]; then
		cat >"$UNITS/scrubline-provision.service" <<UNIT
[Unit]
Description=Scrubline tunnel provisioner
Documentation=file://$REPO/docs/install.md
After=scrubline-node.service network-online.target
Wants=scrubline-node.service

[Service]
EnvironmentFile=$ETC/node.env
ExecStart=$PREFIX/scrub-provision \$SCRUBLINE_PROVISION_OPTS
Restart=always
RestartSec=5
# It changes interfaces, routes, nftables and qdiscs through netlink, and nothing else.
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
$HARDENING

[Install]
WantedBy=multi-user.target
UNIT
	else
		if [[ $SYSTEMD -eq 1 ]]; then
			systemctl disable --now scrubline-provision.service >/dev/null 2>&1 || true
		fi
		rm -f "$UNITS/scrubline-provision.service" "$PREFIX/scrub-provision"
	fi
fi

# What this run was told, as the defaults for the next.
umask 077
for v in LISTEN HOSTNAMES API_URL CA NAME REGION TUNNEL_IP CAPACITY CAPACITY_PPS LOCAL_AS NEXT_HOP PROVISION CUSTOM_TLS; do
	printf '%s=%q\n' "$v" "${!v:-}"
done >"$SETTINGS"

SERVICES=()
if has_api; then SERVICES+=(scrubline-api); fi
if has_node; then SERVICES+=(scrubline-node); fi
if has_node && [[ $PROVISION == 1 ]]; then SERVICES+=(scrubline-provision); fi

if [[ $SYSTEMD -eq 0 ]]; then
	warn "systemd is not running here, so nothing was started; the services are in $UNITS"
	START=0
else
	systemctl daemon-reload
	if [[ $START -eq 1 ]]; then
		say "starting ${SERVICES[*]}"
		systemctl enable "${SERVICES[@]/%/.service}" >/dev/null 2>&1
		systemctl restart "${SERVICES[@]/%/.service}"
	fi
fi

# Waits up to a minute for a check to pass, then says how it went.
FAILED=0
wait_for() {
	local unit=$1 done=$2
	shift 2
	for _ in $(seq 1 60); do
		if "$@" >/dev/null 2>&1; then
			say "$done"
			return 0
		fi
		sleep 1
	done
	warn "$unit did not come up within a minute; see journalctl -u $unit"
	FAILED=1
}
if [[ $START -eq 1 ]]; then
	if has_api; then
		if [[ $CUSTOM_TLS == 1 ]]; then
			wait_for scrubline-api "control plane is running" systemctl is-active --quiet scrubline-api
		else
			wait_for scrubline-api "control plane is up on port $PORT" \
				curl -fsS --cacert "$ETC/tls/ca.pem" "https://127.0.0.1:$PORT/health"
		fi
	fi
	if has_node; then
		wait_for scrubline-node "node $NAME enrolled with $API_URL" curl -fsS http://127.0.0.1:9091/health
		if [[ $PROVISION == 1 ]]; then
			wait_for scrubline-provision "provisioner is applying this node's tunnels" \
				systemctl is-active --quiet scrubline-provision
		fi
	fi
fi

# ---------------------------------------------------------------- what next
echo
HERE=$(addresses | head -n1)
HERE=${HERE:-$(hostname -s)}
if has_api; then
	ca_note=
	if [[ $CUSTOM_TLS == 1 ]]; then ca_note=" (not used: you supplied a certificate)"; fi
	cat <<NEXT
Control plane
  API             https://$HERE:$PORT
  credentials     $ETC/api.env (SCRUBLINE_API_TOKEN, the operator token, is for your panel)
  CA certificate  $ETC/tls/ca.pem$ca_note
  try it          sudo scrubline-ctl nodes

To add a scrubbing node, copy $ETC/tls/ca.pem to it and run there:
  sudo scripts/install.sh node --api https://$HERE:$PORT \\
      --ca /path/to/ca.pem --enroll-token $enroll_token \\
      --name <name> --region <location>

NEXT
fi
if has_node; then
	if [[ $PROVISION == 1 ]]; then
		provisioner="keeps this server's tunnels, routes, firewall and shapers in step with the API"
		logs="journalctl -u scrubline-node -u scrubline-provision"
	else
		provisioner="not installed: apply GET /tunnels?format=iproute2 yourself"
		logs="journalctl -u scrubline-node"
	fi
	cat <<NEXT
Scrubbing node $NAME ($REGION)
  tunnel IP       $TUNNEL_IP: customers' GRE tunnels and the other nodes' tunnels end here
  agent           http://127.0.0.1:9091 (its token is SCRUBLINE_NODE_API_TOKEN in $ETC/node.env)
  provisioner     $provisioner
  logs            $logs

Pin a customer's tunnel to this node from your panel with
  PUT /v1/tunnels/<id>/location {"node":"<this node's id, from GET /v1/nodes>"}
NEXT
fi
exit "$FAILED"
