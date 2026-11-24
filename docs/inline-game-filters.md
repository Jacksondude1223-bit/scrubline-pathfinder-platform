# Inline game-filter enforcement

Without this feature, a node forwards tunnel traffic in the kernel and the game-filter engine only judges flows sent to the agent's `/decide` endpoint. Inline enforcement puts the engine in the forwarding path. Forwarded UDP going down a customer tunnel to an enforcing game filter's port is handed to `scrub-node` on NFQUEUE. The agent judges each packet with the game-filter stage and accepts or drops it before it reaches the customer.

## What is judged

The agent renders queue rules only for game filters that:

- are enforcing, not `observe`;
- have a layer-4 profile (`raknet`, `a2s` or a custom signature);
- are bound to one UDP port (`proto` of `udp`, `any` or empty, and a nonzero `dport`).

TCP is not queued. A TCP handshake segment carries no payload for a profile to judge, and HTTP rules need the connection's context. Those filters keep their current behavior. A filter bound to every port (`dport` 0) is not queued either, because that would send all of a customer's UDP through userspace.

For each customer tunnel built on the node (not port-forwarding or return-only tunnels), there is one rule per protected network and port, scoped to the tunnel's interface and narrowed to the filter's `dst_cidr` when it has one. The rules sit in their own `game_inline` chain at forward priority 20. That is after the `forward` and `forwarded_hosts` chains, so a packet the existing forwarding rules drop never reaches the agent.

Each queued packet goes through the same game-filter logic `decide` uses:

- A source in the penalty box is dropped.
- A trusted source skips the gate but is still held to the protocol's framing.
- An on-demand tunnel under its attack thresholds only watches. The engine still learns sessions, but nothing is dropped.
- Handshake gates (`raknet`, custom `handshake`) drop packets from sources that have not completed the handshake, and admit them once they have.
- The A2S challenge gate drops an unverified query and sends the client a challenge from the server's address and port, through a raw socket. The client's next query carries the cookie and is admitted. The server's own challenge round then passes, because the source is admitted.
- Packets no filter is bound to, and packets the agent cannot read, are accepted.

Drops and challenges count in the stage counters and the per-filter game stats, and strike the source's reputation, as they do through `decide`.

## Failing open

Filtering stops before the customers' traffic does:

- The rules use `bypass`, so the kernel forwards queued packets unjudged when no agent is bound to the queue: the agent is stopped, restarting, or was started without `-inline-queue`.
- The agent binds the queue with `NFQA_CFG_F_FAIL_OPEN` and a 4096-packet limit, so when the agent falls behind the kernel forwards the overflow unjudged instead of dropping it. These show up in `queue_dropped`.
- A packet the agent cannot parse is accepted (`unreadable`).

Both no-agent and stuck-agent behavior are covered by namespace tests in `tests/inline.rs`.

## Enabling it

1. Add `-inline-queue <n>` to `SCRUBLINE_NODE_EXTRA_OPTS` in `/etc/scrubline/node.env`, choosing a queue number nothing else on the box uses (for example `-inline-queue 0`).
2. Run `scripts/install.sh` again. It grants the node service `CAP_NET_ADMIN`, which NFQUEUE needs, only when the extra options contain `-inline-queue`. The agent also uses `CAP_NET_RAW` for the challenge socket.
3. Restart the agent and provisioner: `systemctl restart scrubline-node scrubline-provision`. The agent adds the queue rules to what it serves at `/tunnels`, and the provisioner applies them on its next pass. The kernel loads the `nft_queue` module on demand.
4. Check the node report's `inline_games` status: `active` should be true and `error` empty. `packets`, `accepted`, `dropped` and `challenged` should move with game traffic.

To turn it off, remove the flag and restart the agent. The rules disappear on the provisioner's next pass, and until then `bypass` forwards the traffic unjudged.

## Status

`inline_games` in the node report:

| field | meaning |
|---|---|
| `active` | the queue is bound and being read |
| `queue` | the NFQUEUE number |
| `packets`, `accepted`, `dropped`, `challenged` | packets taken from the queue and their verdicts |
| `replies_failed` | challenges that could not be sent (the packet was still dropped; the client retries) |
| `unreadable` | packets accepted because they could not be parsed |
| `overruns` | times the socket buffer overran; those packets are forwarded once the kernel gives up on them |
| `queue_dropped`, `user_dropped` | from `/proc/net/netfilter/nfnetlink_queue`: packets forwarded unjudged because the queue was full or could not be delivered |
| `error` | why the queue or the challenge socket could not be opened, if it could not |

## Capacity

The judgment is cheap: parsing and judging a packet takes about 0.7 µs on one core in release builds, about 1.3 million packets per second. NFQUEUE itself is the limit: each packet crosses netlink twice, and one verdict is sent per packet. Expect a few hundred thousand packets per second per node on the queued ports. Floods beyond that overflow the queue and are forwarded unjudged by design. The existing kernel limits, ACLs and upstream mitigation still apply to them. Verdicts are judged in batches of up to 64 packets under one hold of the agent's lock, so control-plane requests and inline judging take turns rather than contending per packet.

Possible follow-ups if more is needed: batched verdicts for runs of accepts, several queues with `queue-balance` and per-queue engine shards, or moving framing checks for stateless profiles into nftables or XDP.
