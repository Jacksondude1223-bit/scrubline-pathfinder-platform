# Live discovery on routed tunnel interfaces

The node can observe packets actually crossing configured Linux tunnel interfaces and feed them into passive protocol discovery. Kernel tunnel counters alone cannot provide the port numbers, TCP flags and payload signatures needed to recognize an exchange.

## Configuration

Start scrub-node with `-discovery-interfaces scr-example`. Multiple exact interface names can be separated by commas, up to 16. Capture is disabled when the flag is absent. The observer needs Linux, CAP_NET_RAW and the AF_PACKET address family. The scrubline-node unit written by scripts/install.sh grants both; a node installed before that change must rerun the installer (or add `AmbientCapabilities=CAP_NET_RAW`, `CapabilityBoundingSet=CAP_NET_RAW` and `AF_PACKET` to `RestrictAddressFamilies` in a drop-in), otherwise capture status shows `active: false` with an "Address family not supported" or permission error. No promiscuous mode, firewall rule, route or packet queue is installed.

Use only the interfaces rendered for this node's current protected tunnels. The pipeline accepts a packet only when its protected source or destination belongs both to the compiled node prefixes and to the specified interface's tunnel assignment. Unknown interfaces, removed assignments and other addresses do not contribute discoveries. Interface deletion/recreation is checked every two seconds and opens a new socket for the new interface index. A missing interface or permission failure remains visible in status while the node retries; forwarding is unaffected.

For the investigated WireGuard deployment, the interface for 104.223.81.145/32 was `scr-osfwqbbik2b`. Verify the current assignment before adding that exact name to SCRUBLINE_NODE_EXTRA_OPTS. Preserve any other existing extra options. Restart the node after deploying the reviewed binary and changing its options, then verify capture status and the service's discovered ports.

## Evidence and resource bounds

AF_PACKET SOCK_DGRAM provides the IP packet without an Ethernet header. PACKET_OUTGOING on the tunnel is a request toward the protected origin; PACKET_HOST on the tunnel is a reply from it. Other packet types are ignored. The existing parser rejects malformed, fragmented or truncated packets. TCP discovery still requires a SYN followed by a corresponding SYN-ACK. UDP discovery requires matching addresses/ports in both directions. Steam A2S and RakNet still require their existing request/reply signatures. One valid exchange is visible; automatic installation still requires the panel's two fresh confirmations, protocol opt-in and conflict checks.

The observer reads at most 256 datagrams per 100 ms per configured interface. Each socket requests a bounded 1 MiB receive buffer, subject to the kernel's limits, and the reusable packet buffer is 65,535 bytes. Kernel drops and busy-pipeline samples are reported. This is a bounded discovery sample, so heavy traffic can reduce discovery coverage; it is not a lossless capture guarantee. Packet payloads are not logged or saved. Discovery retains only its existing bounded request/signature state and discovered port records.

Each node report includes discovery_capture keyed by interface, with active state, packets received, accepted observations, invalid/ignored samples, busy samples, kernel drops, last packet time and any socket error. Disabled capture appears as an empty map. Compare this status with discovered_ports and confirm that recognized exchanges continue arriving before expecting the automatic installer to act.

## Scope of the fix

This observer supplies passive discovery evidence. It does not call the live decision tester, change inspection counters or trust/session/rate state, or claim that a sampled decision was enforced against a forwarded packet. Existing kernel forwarding and ACL behavior continue to apply. Enforcing stateful userspace game-filter decisions on live forwarded traffic requires an inline datapath adapter; installing a discovered filter alone is not proof of inline enforcement.

Deploy and enable this independently from the panel. Existing panel discovery settings remain authoritative for observe/enforce installation, including the warning that A2S belongs only on a dedicated query port. Configure the affected service's protocols according to what that server actually runs.
