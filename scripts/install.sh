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
# restarts them, and keeps the credentials, certificates and options from earlier runs.
# scripts/install.sh --help lists every option; docs/install.md walks through a fabric.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=/usr/local/bin
ETC=/etc/scrubline
STATE=/var/lib/scrubline
UNITS=/etc/systemd/system
MODULES=/etc/modules-load.d/scrubline.conf
SYSCTLS=/etc/sysctl.d/90-scrubline.conf
SETTINGS=$ETC/install.conf
# Where the provisioner says how its last pass went.
STATUS=/run/scrubline-provision/status

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}
# Keys and certificates are made here on their way into place, and it goes however the script
# exits.
SCRATCH=''
trap 'if [[ -n $SCRATCH ]]; then rm -rf "$SCRATCH"; fi' EXIT

usage() {
	cat <<'USAGE'
Usage: sudo scripts/install.sh <api|node|all|uninstall> [options]

Control plane (api, all):
  --listen ADDR:PORT      address and port the API serves on (default 0.0.0.0:8080)
  --tls-cert FILE         certificate to serve with, with --tls-key; without them a private
  --tls-key FILE          CA and a certificate for this server are generated
  --hostname NAME         another name or address to put in the generated certificate, such as
                          a public address the nodes reach this server on (repeatable)
  --replica-of URL        follow the primary control plane at URL (api only): serve reads, refuse
                          writes, and be ready to take over
  --primary               run as the primary, as a replica should once it is promoted
  --api-token TOKEN       use this operator token rather than a new one; a replica takes its
                          primary's SCRUBLINE_API_TOKEN
  --enroll-token TOKEN    likewise the enrollment token (SCRUBLINE_ENROLL_TOKEN)
  --ca FILE               with --replica-of: the CA certificate that signed the primary's

Scrubbing node (node, all):
  --api URL               the control plane, e.g. https://10.0.0.5:8080 (all: this server)
  --enroll-token TOKEN    the control plane's enrollment token (all: this server's)
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

Options are kept from one run to the next; to drop one, delete its line from
/etc/scrubline/install.conf and run this again. Flags of the binaries that have no option here go
on the *_EXTRA_OPTS lines in /etc/scrubline/api.env and node.env, which are kept too.
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

# What the operator gave on earlier runs, which this run starts from. Values that follow from
# these are worked out afresh every run, so they follow when an option changes; only a node's
# name, region and tunnel IP are kept once worked out, since the fabric knows the node by them.
LISTEN='' TLS_CERT='' TLS_KEY='' HOSTNAMES='' API_URL='' ENROLL_TOKEN='' CA='' NAME=''
REGION='' TUNNEL_IP='' CAPACITY='' CAPACITY_PPS='' LOCAL_AS='' NEXT_HOP='' PROVISION=''
CUSTOM_TLS='' REPLICA_OF='' FIREWALLD=''
if [[ -f $SETTINGS ]]; then
	# shellcheck source=/dev/null
	. "$SETTINGS"
fi
BIN_DIR='' DEPS=1 START=1 PURGE=0 API_TOKEN=''
EXTRA_HOSTS=()
need() { [[ $# -ge 2 && -n $2 ]] || die "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
	case $1 in
	--listen) need "$@"; LISTEN=$2; shift ;;
	--tls-cert) need "$@"; TLS_CERT=$2; shift ;;
	--tls-key) need "$@"; TLS_KEY=$2; shift ;;
	--hostname) need "$@"; EXTRA_HOSTS+=("$2"); shift ;;
	--replica-of) need "$@"; REPLICA_OF=$2; [[ $ROLE == api ]] || die "--replica-of is for the api role"; shift ;;
	--primary) REPLICA_OF='' ;;
	--api-token) need "$@"; API_TOKEN=$2; shift ;;
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
for h in ${EXTRA_HOSTS[@]+"${EXTRA_HOSTS[@]}"}; do
	[[ $h =~ ^[A-Za-z0-9*.:-]+$ ]] || die "--hostname must be a DNS name or an IP address: '$h'"
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
addresses() { ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true; }
token() { head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n'; }
# The value of KEY in an env file this script wrote, if it is there.
read_env() {
	if [[ -f $1 ]]; then
		sed -n "/^$2=/{s/^$2=//p;q;}" "$1"
	fi
}

# firewalld, which RHEL and its relatives run by default, drops GRE, IPIP and the API's port until
# told otherwise. What this script opens is recorded in FIREWALLD, and uninstalling closes that
# and nothing else.
firewalld_running() { command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; }
open_firewalld() {
	firewalld_running || return 0
	local want=() item
	# The API's port, unless it listens on loopback only.
	if has_api && [[ $lhost != 127.* && $lhost != '[::1]' ]]; then want+=("port=$PORT/tcp"); fi
	if has_node; then want+=(protocol=gre protocol=ipencap); fi
	for item in ${want[@]+"${want[@]}"}; do
		# Open already, whether by an earlier run or by someone else, is left as it is.
		if firewall-cmd --permanent --query-"$item" >/dev/null 2>&1; then continue; fi
		if ! { firewall-cmd --permanent --add-"$item" >/dev/null && firewall-cmd --add-"$item" >/dev/null; }; then
			die "could not open ${item#*=} in firewalld"
		fi
		FIREWALLD="${FIREWALLD:+$FIREWALLD,}$item"
		say "opened ${item#*=} in firewalld"
	done
}
close_firewalld() {
	[[ -n $FIREWALLD ]] && firewalld_running || return 0
	local items=() item
	IFS=, read -r -a items <<<"$FIREWALLD"
	for item in "${items[@]}"; do
		firewall-cmd --permanent --remove-"$item" >/dev/null 2>&1 || true
		firewall-cmd --remove-"$item" >/dev/null 2>&1 || true
	done
	FIREWALLD=''
	say "closed what this script opened in firewalld"
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
	close_firewalld
	rm -f "$PREFIX"/{scrub-api,scrub-node,scrub-provision,scrubctl}
	rm -f "$MODULES" "$SYSCTLS"
	if [[ $PURGE -eq 1 ]]; then
		rm -rf "$ETC" "$STATE"
		if id scrubline >/dev/null 2>&1; then
			userdel scrubline 2>/dev/null || true
		fi
		say "removed Scrubline, its credentials, certificates and state"
	else
		# What is closed is no longer this script's to close.
		if [[ -z $FIREWALLD && -f $SETTINGS ]]; then sed -i '/^FIREWALLD=/d' "$SETTINGS"; fi
		say "removed Scrubline; credentials and state are kept in $ETC and $STATE (--purge removes them)"
	fi
	say "forwarding and reverse-path settings stay as they are until the next boot"
}
if [[ $ROLE == uninstall ]]; then
	uninstall
	exit 0
fi

# ---------------------------------------------------------------- memory
# Scrubline is sized for servers with 16 GB: the control plane at the most it keeps and a node at
# its bounds fit in that with room to spare (README, "Sizing for a 16 GB server"). On less it still
# installs, and says so. A 16 GB server shows the kernel a little less than 16 GiB.
mem_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)
if [[ $mem_kb =~ ^[0-9]+$ ]] && ((mem_kb < 15 * 1024 * 1024)); then
	warn "this server has $(awk -v kb="$mem_kb" 'BEGIN {printf "%.1f", kb / 1048576}') GiB of memory; Scrubline is sized for at least 16 GB (see docs/install.md)"
fi

# ---------------------------------------------------------------- packages
# The commands this role uses, then the packages they come in, which differ between families.
needs=(curl ip)
if has_api; then needs+=(openssl); fi
if has_node; then needs+=(tc nft); fi
packages_for() {
	case $1:$2 in
	*:curl) echo curl ca-certificates ;;
	dnf:ip) echo iproute ;;
	# RHEL 8 and later, and Fedora, split tc out of iproute.
	dnf:tc) echo iproute-tc ;;
	*:ip | *:tc) echo iproute2 ;;
	*:nft) echo nftables ;;
	*:openssl) echo openssl ;;
	esac
}
pm_install() {
	local pm=$1 out
	shift
	case $pm in
	apt) out=$({ DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" ||
		{ apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@"; }; } 2>&1) ;;
	dnf) out=$(dnf install -y -q "$@" 2>&1) ;;
	zypper) out=$(zypper --non-interactive install "$@" 2>&1) ;;
	esac || {
		printf '%s\n' "$out" | tail -n 20 >&2
		return 1
	}
}
missing=()
for c in "${needs[@]}"; do
	command -v "$c" >/dev/null || missing+=("$c")
done
if [[ ${#missing[@]} -gt 0 ]]; then
	[[ $DEPS -eq 1 ]] || die "missing ${missing[*]} (and --no-deps was given)"
	if command -v apt-get >/dev/null; then
		pm=apt
	elif command -v dnf >/dev/null; then
		pm=dnf
	elif command -v zypper >/dev/null; then
		pm=zypper
	else
		die "missing ${missing[*]}, and there is no apt-get, dnf or zypper to install them with"
	fi
	pkgs=()
	for c in "${missing[@]}"; do
		for p in $(packages_for "$pm" "$c"); do
			case " ${pkgs[*]-} " in
			*" $p "*) ;;
			*) pkgs+=("$p") ;;
			esac
		done
	done
	say "installing ${pkgs[*]}"
	pm_install "$pm" "${pkgs[@]}" || die "could not install ${pkgs[*]}; install them and run this again"
	for c in "${missing[@]}"; do
		command -v "$c" >/dev/null || die "there is still no $c after installing ${pkgs[*]}; install it and run this again"
	done
fi

# ---------------------------------------------------------------- settings
listen=${LISTEN:-0.0.0.0:8080}
lhost=${listen%:*}
PORT=${listen##*:}
if [[ $listen != *:* || ! $PORT =~ ^[0-9]{1,5}$ ]] || ((10#$PORT < 1 || 10#$PORT > 65535)) ||
	! { ipv4 "$lhost" || [[ $lhost =~ ^\[[0-9A-Fa-f:.]+\]$ ]]; }; then
	die "--listen must be an address and a port, e.g. 0.0.0.0:8080 or [::]:8080: '$listen'"
fi
# Where this server reaches its own API: loopback when it listens on every address, or the one
# address it listens on.
LOCAL=${lhost#[}
LOCAL=${LOCAL%]}
case $LOCAL in
0.0.0.0 | ::) LOCAL=127.0.0.1 ;;
esac
if [[ $LOCAL == *:* ]]; then LOCAL_URL="https://[$LOCAL]:$PORT"; else LOCAL_URL="https://$LOCAL:$PORT"; fi
if has_api && [[ -n $TLS_CERT || -n $TLS_KEY ]]; then
	[[ -n $TLS_CERT && -n $TLS_KEY ]] || die "--tls-cert and --tls-key go together"
	[[ -f $TLS_CERT && -f $TLS_KEY ]] || die "--tls-cert and --tls-key must be files"
	CUSTOM_TLS=1
fi
# A node registers and reports, which a replica refuses, so this server's own node cannot use it.
if [[ -n $REPLICA_OF && $ROLE != node ]]; then
	[[ $ROLE == api ]] || die "this server's control plane follows $REPLICA_OF, and its own node cannot register with a replica; pass --primary once it has taken over"
	plain --replica-of "$REPLICA_OF"
	[[ $REPLICA_OF == https://* ]] || die "--replica-of must be the primary's https:// URL"
fi
if [[ -n $CA ]]; then
	plain --ca "$CA"
	[[ -f $CA ]] || die "--ca $CA does not exist"
fi
PROVISION=${PROVISION:-1}
if has_node; then
	NAME=${NAME:-$(hostname -s)}
	REGION=${REGION:-default}
	capacity=${CAPACITY:-10}
	capacity_pps=${CAPACITY_PPS:-1000000}
	plain --name "$NAME"
	[[ $NAME != *[/\|]* ]] || die "--name must not contain '/' or '|'"
	plain --region "$REGION"
	[[ $capacity =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--capacity must be a number of Gbit/s"
	[[ $capacity_pps =~ ^[0-9]+$ ]] || die "--capacity-pps must be a whole number"
	[[ -z $LOCAL_AS || $LOCAL_AS =~ ^[0-9]+$ ]] || die "--local-as must be an AS number"
	if [[ -z $TUNNEL_IP ]]; then
		TUNNEL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n '/ src /{s/.* src \([0-9.]*\).*/\1/p;q;}' || true)
		[[ -n $TUNNEL_IP ]] || die "could not work out this server's IPv4 address; pass --tunnel-ip"
	fi
	ipv4 "$TUNNEL_IP" || die "--tunnel-ip must be an IPv4 address: '$TUNNEL_IP'"
	next_hop=${NEXT_HOP:-$TUNNEL_IP}
	ipv4 "$next_hop" || [[ $next_hop =~ ^[0-9A-Fa-f:.]+$ && $next_hop == *:* ]] ||
		die "--bgp-next-hop must be an IP address: '$next_hop'"
	api_url=$API_URL
	if [[ $ROLE == all && -z $api_url ]]; then
		# A certificate of the operator's covers the names they gave it, which need not
		# include the address this server reaches itself on.
		[[ $CUSTOM_TLS != 1 ]] ||
			die "with your own certificate, pass --api with this server's URL as the certificate names it, e.g. https://scrub.example.com:$PORT"
		api_url=$LOCAL_URL
	fi
	[[ -n $api_url ]] || die "--api is required: the control plane's URL, e.g. https://10.0.0.5:8080"
	plain --api "$api_url"
	[[ $api_url == https://* || $api_url == http://127.* || $api_url == http://localhost* ]] ||
		die "--api must be https:// (only a control plane on this server may be reached in the clear)"
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
# The CA of the control plane this server talks to, kept here so the next run needs no copy.
if [[ -n $CA && $CA != "$ETC"/* ]]; then
	install -m 0644 "$CA" "$ETC/api-ca.pem"
	CA=$ETC/api-ca.pem
fi

# ---------------------------------------------------------------- control plane
# Runs openssl, stopping with what it said when it fails.
ossl() {
	local out
	out=$(openssl "$@" 2>&1) || die "openssl $1 failed: $out"
}
# A private CA and a certificate for this server, reissued when its names change or it comes
# within 30 days of expiring. The CA's key stays root's; only the server key is readable by the
# service.
certificates() {
	local tls=$ETC/tls
	install -d -m 0750 -o root -g scrubline "$tls"
	if [[ -n $TLS_CERT ]]; then
		install -m 0644 "$TLS_CERT" "$tls/server.pem"
		install -m 0640 -g scrubline "$TLS_KEY" "$tls/server-key.pem"
		# Not this script's certificate, so one is issued again if the operator's is dropped.
		rm -f "$tls/server.sans"
		return
	fi
	if [[ $CUSTOM_TLS == 1 && -f $tls/server.pem ]]; then
		return
	fi
	CUSTOM_TLS=0
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
	extra+=("$LOCAL")
	for h in "${extra[@]}"; do
		case ",$sans," in
		*",IP:$h,"* | *",DNS:$h,"*) continue ;;
		esac
		[[ -n $h ]] || continue
		if ipv4 "$h" || [[ $h == *:* ]]; then sans+=",IP:$h"; else sans+=",DNS:$h"; fi
	done
	SCRATCH=$(mktemp -d)
	# Everything the certificates carry is in this file, so whatever the distribution's own
	# openssl.cnf would add stays out of them.
	cat >"$SCRATCH/openssl.cnf" <<CNF
[req]
distinguished_name = subject
[subject]
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = $sans
CNF
	if [[ ! -f $tls/ca.pem || ! -f $tls/ca-key.pem ]]; then
		say "creating a private CA in $tls"
		ossl req -config "$SCRATCH/openssl.cnf" -extensions ca -x509 \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-keyout "$SCRATCH/ca-key.pem" -out "$SCRATCH/ca.pem" -days 3650 \
			-subj "/CN=Scrubline CA $(hostname -s)"
		install -m 0600 "$SCRATCH/ca-key.pem" "$tls/ca-key.pem"
		install -m 0644 "$SCRATCH/ca.pem" "$tls/ca.pem"
		rm -f "$tls/server.pem"
	fi
	if ! openssl x509 -checkend $((825 * 86400)) -noout -in "$tls/ca.pem" >/dev/null; then
		warn "the private CA in $tls expires $(openssl x509 -enddate -noout -in "$tls/ca.pem" | cut -d= -f2), before a certificate issued now would; make a new one (move ca.pem and ca-key.pem aside and run this again) and give it to every node"
	fi
	if [[ -f $tls/server.pem && "$(cat "$tls/server.sans" 2>/dev/null)" == "$sans" ]] &&
		openssl x509 -checkend 2592000 -noout -in "$tls/server.pem" >/dev/null; then
		return
	fi
	say "issuing a certificate for this server ($sans)"
	ossl req -config "$SCRATCH/openssl.cnf" -new \
		-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout "$SCRATCH/key.pem" -out "$SCRATCH/req.csr" -subj "/CN=$(hostname -s)"
	ossl x509 -req -in "$SCRATCH/req.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca-key.pem" \
		-CAcreateserial -CAserial "$tls/ca.srl" -out "$SCRATCH/cert.pem" -days 825 \
		-extfile "$SCRATCH/openssl.cnf" -extensions server
	install -m 0644 "$SCRATCH/cert.pem" "$tls/server.pem"
	install -m 0640 -g scrubline "$SCRATCH/key.pem" "$tls/server-key.pem"
	printf '%s' "$sans" >"$tls/server.sans"
}

if has_api; then
	certificates
	api_token=${API_TOKEN:-$(read_env "$ETC/api.env" SCRUBLINE_API_TOKEN)}
	enroll_token=${ENROLL_TOKEN:-$(read_env "$ETC/api.env" SCRUBLINE_ENROLL_TOKEN)}
	if [[ -n $REPLICA_OF && (-z $api_token || -z $enroll_token) ]]; then
		die "a replica serves with its primary's tokens: pass --api-token and --enroll-token with SCRUBLINE_API_TOKEN and SCRUBLINE_ENROLL_TOKEN from the primary's $ETC/api.env"
	fi
	api_token=${api_token:-$(token)}
	enroll_token=${enroll_token:-$(token)}
	plain --api-token "$api_token"
	plain --enroll-token "$enroll_token"
	[[ $api_token != "$enroll_token" ]] || die "the operator and enrollment tokens must differ"
	opts="-addr $listen -state $STATE/state.json -tls-cert $ETC/tls/server.pem -tls-key $ETC/tls/server-key.pem"
	if [[ -n $REPLICA_OF ]]; then
		opts+=" -role replica -primary $REPLICA_OF"
		if [[ -n $CA ]]; then opts+=" -ca $CA"; fi
	fi
	cat >"$ETC/api.env.new" <<ENV
# Written by scripts/install.sh, which rewrites it on every run and keeps the tokens and the
# extra options. Change the others by running it again with them. Flags it has no option for go
# on SCRUBLINE_API_EXTRA_OPTS, and win over its own; then systemctl restart scrubline-api. The
# tokens are secrets: the operator token can change everything, and every node holds the other.
SCRUBLINE_API_TOKEN=$api_token
SCRUBLINE_ENROLL_TOKEN=$enroll_token
SCRUBLINE_API_OPTS=$opts
SCRUBLINE_API_EXTRA_OPTS=$(read_env "$ETC/api.env" SCRUBLINE_API_EXTRA_OPTS)
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
exec $PREFIX/scrubctl -api $LOCAL_URL -ca $ETC/tls/ca.pem "\$@"
CTL
		install -m 0750 "$PREFIX/scrubline-ctl.new" "$PREFIX/scrubline-ctl"
		rm -f "$PREFIX/scrubline-ctl.new"
	fi
fi

# ---------------------------------------------------------------- scrubbing node
if has_node; then
	ca=$CA
	if [[ $ROLE == all ]]; then
		ENROLL_TOKEN=$enroll_token
		if [[ -z $ca && $CUSTOM_TLS != 1 ]]; then ca=$ETC/tls/ca.pem; fi
	fi
	ENROLL_TOKEN=${ENROLL_TOKEN:-$(read_env "$ETC/node.env" SCRUBLINE_ENROLL_TOKEN)}
	[[ -n $ENROLL_TOKEN ]] || die "--enroll-token is required: SCRUBLINE_ENROLL_TOKEN from the control plane's $ETC/api.env"
	plain --enroll-token "$ENROLL_TOKEN"
	node_token=$(read_env "$ETC/node.env" SCRUBLINE_NODE_API_TOKEN)
	node_token=${node_token:-$(token)}
	opts="-api $api_url -name $NAME -region $REGION -capacity $capacity -capacity-pps $capacity_pps"
	opts+=" -listen 127.0.0.1:9091 -advertise $TUNNEL_IP:9091 -tunnel-src $TUNNEL_IP -bgp-next-hop $next_hop"
	if [[ -n $LOCAL_AS ]]; then
		opts+=" -local-as $LOCAL_AS"
	fi
	if [[ -n $ca ]]; then
		opts+=" -ca $ca"
	fi
	cat >"$ETC/node.env.new" <<ENV
# Written by scripts/install.sh, which rewrites it on every run and keeps the tokens and the
# extra options. Change the others by running it again with them. Flags it has no option for go
# on SCRUBLINE_NODE_EXTRA_OPTS or SCRUBLINE_PROVISION_EXTRA_OPTS, and win over its own; then
# systemctl restart scrubline-node scrubline-provision.
SCRUBLINE_ENROLL_TOKEN=$ENROLL_TOKEN
SCRUBLINE_NODE_API_TOKEN=$node_token
SCRUBLINE_NODE_OPTS=$opts
SCRUBLINE_NODE_EXTRA_OPTS=$(read_env "$ETC/node.env" SCRUBLINE_NODE_EXTRA_OPTS)
SCRUBLINE_PROVISION_OPTS=-agent http://127.0.0.1:9091 -status $STATUS
SCRUBLINE_PROVISION_EXTRA_OPTS=$(read_env "$ETC/node.env" SCRUBLINE_PROVISION_EXTRA_OPTS)
ENV
	install -m 0640 -o root -g scrubline "$ETC/node.env.new" "$ETC/node.env"
	rm -f "$ETC/node.env.new"

	# The kernel side of tunnels: GRE and IPIP, forwarding, and reverse-path filtering loose
	# enough for a customer's replies to come up a tunnel for a prefix this node routes elsewhere.
	printf 'ip_gre\nipip\n' >"$MODULES"
	chmod 0644 "$MODULES"
	if ! { modprobe ip_gre && modprobe ipip; } 2>/dev/null; then
		warn "could not load the ip_gre and ipip modules now; they load at the next boot"
	fi
	{
		printf '%s\n' "# Written by scripts/install.sh for a Scrubline scrubbing node."
		if [[ -d /proc/sys/net/ipv6 ]]; then
			# Turning forwarding on drops the default routes router advertisements gave every
			# interface not set to keep taking them, so those set first: the interfaces with such
			# a route now, and those an earlier run set, whose route may not be back yet.
			for dev in $({
				ip -6 route show default proto ra 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p'
				if [[ -f $SYSCTLS ]]; then sed -n 's|^net/ipv6/conf/\([^/]*\)/accept_ra = 2$|\1|p' "$SYSCTLS"; fi
			} | sort -u); do
				printf 'net/ipv6/conf/%s/accept_ra = 2\n' "$dev"
			done
			printf '%s\n' "net.ipv6.conf.all.forwarding = 1"
		fi
		printf '%s\n' "net.ipv4.ip_forward = 1" \
			"net.ipv4.conf.all.rp_filter = 2" \
			"net.ipv4.conf.default.rp_filter = 2"
	} >"$SYSCTLS.new"
	chmod 0644 "$SYSCTLS.new"
	mv -f "$SYSCTLS.new" "$SYSCTLS"
	if ! out=$(sysctl -q -p "$SYSCTLS" 2>&1); then
		warn "could not apply all of $SYSCTLS: $out"
	fi
fi
open_firewalld
if has_node && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
	warn "ufw is active: it must let GRE and IPIP (IP protocols 47 and 4) in from the other nodes and the customers' tunnel ends"
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
ExecStart=$PREFIX/scrub-api \$SCRUBLINE_API_OPTS \$SCRUBLINE_API_EXTRA_OPTS
Restart=on-failure
RestartSec=2
StateDirectory=scrubline
StateDirectoryMode=0750
LimitNOFILE=65536
# At the most it keeps, a full fabric, it holds about 3G (tests/memory.rs); past 8G the kernel
# reclaims from it, and at 10G it is restarted rather than left to starve the server.
MemoryHigh=8G
MemoryMax=10G
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
ExecStart=$PREFIX/scrub-node \$SCRUBLINE_NODE_OPTS \$SCRUBLINE_NODE_EXTRA_OPTS
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
# At its bounds the agent holds under 300M (tests/memory.rs), so 2G is a fault, not load. It is the
# last thing here the kernel should kill for memory: the scrubbing goes with it.
MemoryHigh=1536M
MemoryMax=2G
OOMScoreAdjust=-500
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
ExecStart=$PREFIX/scrub-provision \$SCRUBLINE_PROVISION_OPTS \$SCRUBLINE_PROVISION_EXTRA_OPTS
Restart=always
RestartSec=5
# How its last pass went, in $STATUS; gone when it stops.
RuntimeDirectory=scrubline-provision
MemoryMax=512M
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

# What the operator gave, and the node's identity, for the next run.
umask 077
for v in LISTEN HOSTNAMES API_URL CA NAME REGION TUNNEL_IP CAPACITY CAPACITY_PPS LOCAL_AS NEXT_HOP \
	PROVISION CUSTOM_TLS REPLICA_OF FIREWALLD; do
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
		out=$(systemctl enable "${SERVICES[@]/%/.service}" 2>&1) || die "could not enable ${SERVICES[*]}: $out"
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
# Waits for the provisioner to finish a pass, and says how it went. Until the control plane has a
# policy for this node there is nothing to apply, which it gives a few passes to be sure of.
provisioned() {
	local line='' waiting=0
	for _ in $(seq 1 60); do
		line=$(cat "$STATUS" 2>/dev/null || true)
		case $line in
		ok:*)
			say "provisioner: ${line#ok: }"
			return 0
			;;
		waiting:*)
			if ((++waiting >= 15)); then
				say "provisioner is running; ${line#waiting: }, so it applies this node's tunnels once a policy is deployed"
				return 0
			fi
			;;
		esac
		sleep 1
	done
	warn "the provisioner has not applied this node's configuration (${line:-no pass has finished}); see journalctl -u scrubline-provision"
	FAILED=1
}
local_curl() { curl -fsS --noproxy '*' "$@"; }
if [[ $START -eq 1 ]]; then
	if has_api; then
		if [[ $CUSTOM_TLS == 1 ]]; then
			# Only whether it answers: the certificate is for names this server may not resolve.
			wait_for scrubline-api "control plane is up on port $PORT" local_curl -k "$LOCAL_URL/health"
		else
			wait_for scrubline-api "control plane is up on port $PORT" \
				local_curl --cacert "$ETC/tls/ca.pem" "$LOCAL_URL/health"
		fi
	fi
	if has_node; then
		wait_for scrubline-node "node $NAME enrolled with $api_url" local_curl http://127.0.0.1:9091/health
		if [[ $PROVISION == 1 ]]; then
			provisioned
		fi
	fi
fi

# ---------------------------------------------------------------- what next
echo
HERE=$(addresses | sed -n 1p)
HERE=${HERE:-$(hostname -s)}
if [[ $HERE == *:* ]]; then HERE="[$HERE]"; fi
# The address other servers reach the API on: this server's, when it listens on every address.
case $lhost in
0.0.0.0 | '[::]') API_HERE=https://$HERE:$PORT ;;
*) API_HERE=$LOCAL_URL ;;
esac
if has_api; then
	if [[ $LOCAL == 127.* || $LOCAL == ::1 ]]; then
		warn "the API listens on loopback only, so nodes on other servers cannot reach it; use --listen 0.0.0.0:$PORT for them"
	fi
	if [[ $CUSTOM_TLS == 1 ]]; then
		API_HERE=${API_URL:-"https://<a name your certificate is for>:$PORT"}
	fi
	role="Control plane"
	if [[ -n $REPLICA_OF ]]; then role="Control plane, a replica of $REPLICA_OF"; fi
	printf '%s\n' "$role" "  API             $API_HERE" \
		"  credentials     $ETC/api.env (SCRUBLINE_API_TOKEN, the operator token, is for your panel)"
	if [[ $CUSTOM_TLS != 1 ]]; then
		printf '%s\n' "  CA certificate  $ETC/tls/ca.pem" "  try it          sudo $PREFIX/scrubline-ctl nodes"
	fi
	echo
	if [[ -n $REPLICA_OF ]]; then
		cat <<NEXT
It serves reads and refuses writes. To take over from the primary, promote it:
  curl -X POST --cacert $ETC/tls/ca.pem -H "Authorization: Bearer \$SCRUBLINE_API_TOKEN" $API_HERE/v1/promote
then run sudo scripts/install.sh api --primary here, so it stays the primary when it restarts.

NEXT
	elif [[ $CUSTOM_TLS == 1 ]]; then
		cat <<NEXT
To add a scrubbing node, run there, adding --ca with the certificate of the CA that issued yours
if the node does not trust it already:
  sudo scripts/install.sh node --api $API_HERE \\
      --enroll-token $enroll_token --name <name> --region <location>

NEXT
	else
		cat <<NEXT
To add a scrubbing node, copy $ETC/tls/ca.pem to it and run there:
  sudo scripts/install.sh node --api $API_HERE \\
      --ca /path/to/ca.pem --enroll-token $enroll_token \\
      --name <name> --region <location>

NEXT
	fi
fi
if has_node; then
	if [[ $PROVISION == 1 ]]; then
		provisioner="keeps this server's tunnels, routes, firewall and shapers in step with the API ($STATUS says how)"
		logs="journalctl -u scrubline-node -u scrubline-provision"
	else
		provisioner="not installed: apply GET /tunnels?format=iproute2 yourself"
		logs="journalctl -u scrubline-node"
	fi
	node_id=$(local_curl http://127.0.0.1:9091/health 2>/dev/null | sed -n 's/.*"node":"\([^"]*\)".*/\1/p' || true)
	pin=${node_id:-"<this node's id, from GET /v1/nodes>"}
	cat <<NEXT
Scrubbing node $NAME ($REGION)
  node id         ${node_id:-unknown until it enrols}
  tunnel IP       $TUNNEL_IP: customers' GRE tunnels and the other nodes' tunnels end here
  agent           http://127.0.0.1:9091 (its token is SCRUBLINE_NODE_API_TOKEN in $ETC/node.env)
  provisioner     $provisioner
  logs            $logs

Pin a customer's tunnel to this node from your panel with
  PUT /v1/tunnels/<id>/location {"node":"$pin"}
NEXT
fi
exit "$FAILED"
