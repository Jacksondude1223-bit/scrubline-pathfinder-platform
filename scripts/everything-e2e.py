"""Every feature a policy can turn on, on one node, through the real binaries: the policy in
configs/policy.everything.json deployed through scrub-api onto a scrub-node, traffic driven through
the node's own API, whole packets built to harm the stack that receives them among it, what the
node renders read back and handed to the provisioner's dry run, and the control plane restarted
from its state with the node still at work."""
import base64
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / os.environ.get('PATHFINDER_BIN_DIR', 'target/debug')
ENV = dict(os.environ, SCRUBLINE_API_TOKEN='everything-operator',
           SCRUBLINE_ENROLL_TOKEN='everything-enroll',
           SCRUBLINE_NODE_API_TOKEN='everything-node-local')
OP = ENV['SCRUBLINE_API_TOKEN']; LOCAL = ENV['SCRUBLINE_NODE_API_TOKEN']
processes = []
logs = []

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def start(binary, *args):
    log = tempfile.TemporaryFile(); logs.append(log)
    process = subprocess.Popen([str(BIN / binary), *map(str, args)], cwd=ROOT,
                               env=ENV, stdout=log, stderr=log)
    processes.append(process)
    return process

def stop(process):
    process.terminate(); process.wait(timeout=15)

def call(base, path, method='GET', token=None, data=None, expected=200, text=False):
    headers = {}
    if token is not None: headers['Authorization'] = 'Bearer ' + token
    raw = None if data is None else json.dumps(data).encode()
    if raw is not None: headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(base + path, data=raw, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    assert status == expected, (method, path, status, body[:500])
    return body.decode() if text else json.loads(body or b'null')

def wait_for(check, seconds=20, every=0.1):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            result = check()
            if result: return result
        except (OSError, AssertionError, KeyError, ValueError, TypeError) as error:
            last = error
        time.sleep(every)
    raise AssertionError(('timed out waiting for condition', last))

def flow(proto, src, dst, dport, pps=1, payload=b'', **extra):
    return dict(proto=proto, src_ip=src, dst_ip=dst, sport=extra.pop('sport', 50000), dport=dport,
                pps=pps, payload=base64.b64encode(payload).decode(), **extra)

def ipv4(src, dst, proto, l4, ident=0x1234, frag=0x4000):
    """An IPv4 packet; frag holds the flags and the offset in 8-byte units."""
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, frag, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    total = sum(struct.unpack('!10H', header))
    while total > 0xffff:
        total = (total & 0xffff) + (total >> 16)
    return header[:10] + struct.pack('!H', ~total & 0xffff) + header[12:] + l4

def ipv6(src, dst, next_header, l4):
    return (struct.pack('!IHBB', 6 << 28, len(l4), next_header, 64) +
            socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + l4)

def tcp(sport, dport, flags, options=b''):
    return struct.pack('!HHIIBBHHH', sport, dport, 1, 0, (5 + len(options) // 4) << 4, flags,
                       65535, 0, 0) + options

def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data

def raw(packet, **extra):
    return dict(packet=base64.b64encode(packet).decode(), **extra)

def get(src, path):
    request = (f'GET {path} HTTP/1.1\r\nHost: 203.0.113.20:30120\r\nUser-Agent: CitizenFX/1\r\n'
               'Accept: */*\r\nAccept-Encoding: gzip\r\n\r\n').encode()
    return flow('tcp', src, '203.0.113.20', 30120, payload=request)

try:
    workdir = tempfile.TemporaryDirectory()
    state = pathlib.Path(workdir.name) / 'state.json'
    api_port = port(); base = f'http://127.0.0.1:{api_port}'
    api = start('scrub-api', '-addr', f'127.0.0.1:{api_port}', '-state', state)
    wait_for(lambda: call(base, '/health')['status'] == 'ok')
    node_port = port(); local = f'http://127.0.0.1:{node_port}'
    start('scrub-node', '-api', base, '-listen', f'127.0.0.1:{node_port}', '-name', 'lhr-1',
          '-region', 'lhr', '-capacity', 40, '-capacity-pps', 2000000, '-local-as', 64512,
          '-bgp-next-hop', '192.0.2.1', '-tunnel-src', '192.0.2.1')
    node_id = wait_for(lambda: call(local, '/health'))['node']

    # The policy, its customers, their tunnels and both classifiers.
    policy = json.loads((ROOT / 'configs/policy.everything.json').read_text())
    policy['tunnels'][0]['node'] = node_id
    call(base, '/v1/policies', 'POST', OP, policy)
    call(base, '/v1/policies/everything/deploy', 'POST', OP, {})
    keep = {'id', 'prefixes', 'type', 'remote', 'key', 'direction', 'rate_mbps', 'node',
            'mitigation', 'attack_pps', 'attack_mbps', 'comment'}
    tenants = {}
    for name, prefix in [('northwind', '203.0.113.0/24'), ('contoso', '198.51.100.0/24'),
                         ('fabrikam', '2001:db8:100::/48')]:
        tenants[name] = call(base, '/v1/tenants', 'POST', OP,
                             {'name': name, 'prefixes': [prefix]})['id']
        saved = next(t for t in call(base, '/v1/tunnels', token=OP)['tunnels'] if t['id'] == name)
        saved = {k: v for k, v in saved.items() if k in keep and v is not None}
        saved['tenant'] = tenants[name]
        call(base, f'/v1/tunnels/{name}', 'PUT', OP, saved)
    call(base, '/v1/ml/samples', 'POST', OP, json.loads((ROOT / 'configs/ml.samples.json').read_text()))
    call(base, '/v1/ml/train', 'POST', OP, {'epochs': 30, 'lr': 0.2, 'threshold': 0.65})
    wait_for(lambda: len(call(local, '/tunnels', token=LOCAL)['tunnels']) == 3)
    wait_for(lambda: call(base, f'/v1/nodes/{node_id}/stats', token=OP)['stats']['ml']['http_ready'])

    # Traffic through the node's own API, every stage and filter at once.
    def decide(f):
        return call(local, '/decide', 'POST', LOCAL, f)
    def expect(f, action, reason):
        d = decide(f)
        assert (d['action'], d['reason']) == (action, reason), (f['src_ip'], f['dst_ip'], d)
        return d
    expect(flow('udp', '192.0.2.250', '203.0.113.10', 19132, payload=b'\x84'), 'permit', 'TCAM ACL permit')
    expect(flow('udp', '100.64.0.53', '203.0.113.10', 40000, 10, b'answer', sport=53), 'drop', 'TCAM ACL drop')
    expect(flow('udp', '100.64.0.1', '203.0.113.10', 19132, 250000, b'\x84'), 'drop', 'FPGA meter 200000 pps exceeded')
    expect(flow('udp', '100.64.1.1', '203.0.113.10', 19132, payload=b'\x84\x00\x00'), 'drop',
           'game filter raknet: packet id 0x84 from a source that has not completed the handshake')
    for step in [b'\x05', b'\x07', b'\x84\x00\x00']:
        expect(flow('udp', '192.0.2.10', '203.0.113.10', 19132, payload=step), 'permit', 'PF_RING ZC ml pass')
    query = b'\xff\xff\xff\xffTSource Engine Query\x00'
    challenged = decide(flow('udp', '192.0.2.11', '203.0.113.10', 27015, payload=query))
    assert challenged['action'] == 'challenge', challenged
    cookie = base64.b64decode(challenged['reply'])[5:9]
    expect(flow('udp', '192.0.2.11', '203.0.113.10', 27015, payload=query + cookie), 'permit', 'PF_RING ZC ml pass')
    expect(get('192.0.2.12', '/players.json'), 'permit', 'PF_RING ZC ml pass')
    expect(get('192.0.2.12', '/players.json'), 'drop',
           'game filter http: GET /players.json: more than 1 request a second to this path from this source')
    expect(get('192.0.2.13', '/admin/ban'), 'drop', 'game filter http: GET /admin/ban: the path is blocked')
    flood = decide(flow('tcp', '100.64.1.3', '203.0.113.20', 30120,
                        payload=b'GET /players.json?_=3c9e HTTP/1.0\r\n\r\n'))
    assert flood['action'] == 'drop' and 'by the request model' in flood['reason'], flood
    expect(flow('udp', '2001:db8:ffff::1', '2001:db8:100::10', 19132, payload=b'\x84\x00\x00'), 'drop',
           'game filter raknet: packet id 0x84 from a source that has not completed the handshake')
    # Contoso is watched until attacked, its storefront's HTTP rules apart.
    watching = 'watching only: tunnel contoso is under its attack thresholds'
    reflected = flow('udp', '100.64.5.53', '198.51.100.10', 40000, 10, b'answer', sport=53)
    expect(reflected, 'permit', watching)
    expect(flow('tcp', '100.64.5.1', '198.51.100.80', 80,
                payload=b'GET /wp-admin/setup.php HTTP/1.1\r\nHost: shop\r\n\r\n'), 'drop',
           'game filter http: GET /wp-admin/setup.php: the path is blocked')
    expect(dict(reflected, pps=150000), 'drop', 'TCAM ACL drop')
    expect(reflected, 'drop', 'TCAM ACL drop')
    # A client the origin keeps answering takes the short path.
    for _ in range(3):
        call(local, '/egress', 'POST', LOCAL,
             {'src_ip': '203.0.113.20', 'dst_ip': '192.0.2.20', 'proto': 'udp', 'pps': 4})
        time.sleep(0.26)
    expect(flow('udp', '192.0.2.20', '203.0.113.20', 30120, payload=b'\x01\x02\x03\x04'), 'permit',
           'verified source, fast path')
    # A stranger that keeps failing the handshake is boxed, and an operator can let it out.
    junk = flow('udp', '100.64.2.1', '203.0.113.10', 19132, payload=b'\x84\x00\x00')
    for _ in range(4): decide(junk)
    expect(junk, 'drop', 'source is in the penalty box')
    assert call(local, '/reputation', 'POST', LOCAL, {'release': ['100.64.2.1']})['released'] == 1
    assert call(local, '/reputation?limit=10', token=LOCAL)['stats']['demotions'] == 1
    # Whole packets off the wire: the node reads them itself, passes a real stack's and drops
    # those built to harm one, whoever sends them.
    expect(raw(ipv4('192.0.2.60', '203.0.113.10', 17, udp(53000, 19132, b'\x05'))), 'permit',
           'PF_RING ZC ml pass')
    datagram = udp(53000, 19132, bytes(1016))
    first = ipv4('192.0.2.63', '203.0.113.10', 17, datagram[:512], ident=0x777, frag=0x2000)
    # The game filter takes the first fragment's zeros for junk; the checks just remember it.
    assert 'check' not in decide(raw(first))
    for packet, check in [
        (ipv4('203.0.113.10', '203.0.113.10', 6, tcp(80, 80, 0x02)), 'land'),
        (ipv4('192.0.2.61', '203.0.113.10', 6, tcp(40000, 443, 0x03)), 'tcp_flags'),
        (ipv4('192.0.2.250', '203.0.113.10', 6, tcp(40000, 443, 0x29)), 'tcp_flags'),
        (ipv4('192.0.2.62', '203.0.113.10', 1, bytes(100), frag=8191), 'oversize'),
        (ipv4('192.0.2.64', '203.0.113.10', 6, tcp(40000, 443, 0x02, bytes([2, 4, 0, 48]))), 'low_mss'),
        (ipv4('192.0.2.63', '203.0.113.10', 17, datagram[256:320], ident=0x777, frag=256 // 8),
         'fragment_overlap'),
        (ipv6('2001:db8:ffff::1', '2001:db8:100::10', 58, bytes([134, 0, 0, 0]) + bytes(12)), 'icmp'),
        (ipv4('192.0.2.65', '198.51.100.10', 6, tcp(40000, 443, 0x00)), 'tcp_flags'),
    ]:
        d = decide(raw(packet))
        assert (d['action'], d.get('check')) == ('drop', check), (check, d)
    crafted_flood = flow('tcp', '100.64.9.1', '203.0.113.10', 443, 100000, flags='syn,fin')
    assert decide(crafted_flood)['check'] == 'tcp_flags'
    # A domain controller's CLDAP answer reflected at the game server, in the three fragments a
    # 3,000-byte answer takes, then a player whose NAT maps them to port 389.
    answer = bytes([0x30, 0x84, 0x00, 0x00, 0x0b, 0xb0, 0x02, 0x01, 0x01, 0x64]).ljust(3000, b'\x04')
    first = udp(389, 19132, answer[:1472])[:4] + struct.pack('!H', 8 + len(answer)) + b'\0\0' + answer[:1472]
    pieces = [ipv4('198.18.7.7', '203.0.113.10', 17, first, ident=0x77, frag=0x2000),
              ipv4('198.18.7.7', '203.0.113.10', 17, answer[1472:2952], ident=0x77, frag=0x2000 | 185),
              ipv4('198.18.7.7', '203.0.113.10', 17, answer[2952:], ident=0x77, frag=370)]
    stages = [(d['action'], d['stage'], d.get('reflection')) for d in map(decide, map(raw, pieces))]
    assert stages == [('drop', 'asic', 'cldap'), ('drop', 'zc', 'cldap'), ('drop', 'zc', 'cldap')], stages
    cldap_flood = flow('udp', '198.18.7.8', '203.0.113.10', 19132, 100000, answer[:64], sport=389)
    assert decide(cldap_flood)['reflection'] == 'cldap'
    natted = flow('udp', '192.0.2.251', '203.0.113.10', 19132, payload=b'\x84', sport=389)
    assert 'reflection' not in decide(natted)
    # A botnet's GRE flood, as a packet carrying IPv4 and as records naming GRE or its number.
    gre = b'\x00\x00\x08\x00' + ipv4('1.2.3.4', '5.6.7.8', 17, udp(12345, 12345, b''))
    for f in [raw(ipv4('100.64.9.47', '203.0.113.10', 47, gre)),
              flow('gre', '100.64.9.48', '203.0.113.10', 0, 100000, sport=0),
              flow('47', '100.64.9.49', '203.0.113.10', 0, 1, sport=0)]:
        d = decide(f)
        assert (d['action'], d['stage'], d.get('guard')) == ('drop', 'asic', 'protocol'), d

    # What the node renders for its speaker, its provisioner and BIRD.
    exabgp = call(local, '/bgp?format=exabgp', token=LOCAL, text=True).splitlines()
    assert exabgp == [
        'announce route 198.51.100.0/24 next-hop 192.0.2.1 community [ 64512:200 no-export ]',
        'announce route 2001:db8:100::/48',
        'announce route 203.0.113.0/24 next-hop 192.0.2.1 community [ 64512:100 ]',
    ], exabgp
    iproute2 = call(local, '/tunnels?format=iproute2', token=LOCAL, text=True)
    for tunnel in ['northwind', 'contoso', 'fabrikam']:
        assert f'ip link add scr-{tunnel} type gre' in iproute2, iproute2
    bird = call(local, '/sessions?format=bird', token=LOCAL, text=True)
    assert 'protocol bgp cust_contoso_edge' in bird and 'neighbor 198.18.0.20 as 64600;' in bird, bird
    metrics = call(local, '/metrics', token=LOCAL, text=True)
    for series in ['scrubline_tunnel_mitigating{', 'scrubline_game_http_requests_total{',
                   'scrubline_bgp_announced{', 'scrubline_reputation_freed_total{']:
        assert series in metrics, series
    counted = {line.split('check="')[1].split('"')[0]: float(line.rsplit(' ', 1)[1])
               for line in metrics.splitlines() if line.startswith('scrubline_crafted_dropped_total{')}
    assert counted['land'] == 1 and counted['tcp_flags'] == 4 and counted['fragment_overlap'] == 1, counted
    assert 'mode="enforce"} 1' in metrics, metrics
    gre_total = [line for line in metrics.splitlines()
                 if line.startswith('scrubline_protocol_dropped_total{') and 'protocol="gre"' in line]
    assert gre_total and gre_total[0].endswith(' 3'), gre_total
    assert 'scrubline_ack_flood_mode{' in metrics, metrics
    reflected_total = [line for line in metrics.splitlines()
                       if line.startswith('scrubline_reflection_dropped_total{')]
    assert reflected_total and reflected_total[0].endswith(' 2'), reflected_total
    assert any(line.startswith('scrubline_reflection_fragments_dropped_total{') and line.endswith(' 2')
               for line in metrics.splitlines()), metrics
    dry = subprocess.run([str(BIN / 'scrub-provision'), '-agent', local, '-once', '-dry-run'],
                         env=ENV, capture_output=True, text=True, timeout=30)
    assert dry.returncode == 0, (dry.stdout, dry.stderr)
    for tunnel in ['northwind', 'contoso', 'fabrikam']:
        assert f'ip link add scr-{tunnel} type gre' in dry.stdout, dry.stdout

    # The control plane hears all of it: the mitigation, the metrics and each customer's view.
    def mitigating():
        rows = next(t for t in call(base, '/v1/tunnels', token=OP)['tunnels'] if t['id'] == 'contoso')
        return rows['nodes'][0].get('mitigating') and rows['nodes'][0]
    assert wait_for(mitigating)['mitigation_wave'] == 1
    assert 'scrubline_control_ml_false_positive_rate' in call(base, '/metrics', token=OP, text=True)
    tokens = {}
    for name, prefix in [('northwind', '203.0.113.0/24'), ('contoso', '198.51.100.0/24'),
                         ('fabrikam', '2001:db8:100::/48')]:
        token = tokens[name] = call(base, f'/v1/tenants/{tenants[name]}/token', 'POST', OP, {})['token']
        def sees_only_its_own():
            rows = call(base, '/v1/analytics/overview', token=token)['prefixes']
            return [r['prefix'] for r in rows] == [prefix]
        wait_for(sees_only_its_own)
    # Northwind's attack says the checks stopped part of it.
    def stopped_by_the_checks():
        events = call(base, '/v1/analytics/events', token=tokens['northwind'])['events']
        return any(v.get('crafted') == 'stack' for e in events for v in e.get('vectors', []))
    wait_for(stopped_by_the_checks)
    # And that reflected CLDAP and a GRE flood were part of it.
    for vector in [('reflection', 'cldap'), ('protocol', 'gre')]:
        wait_for(lambda: any(v.get(vector[0]) == vector[1]
                             for e in call(base, '/v1/analytics/events', token=tokens['northwind'])['events']
                             for v in e.get('vectors', [])))
    assert wait_for(lambda: call(base, f'/v1/nodes/{node_id}/stats', token=OP)['stats']['crafted']['dropped'] >= 9)

    # Restarted from its state, the control plane compiles the node the same program once the
    # node, which kept filtering on the one it had, reports in again.
    before = call(base, f'/v1/nodes/{node_id}/program', token=OP)
    stop(api)
    start('scrub-api', '-addr', f'127.0.0.1:{api_port}', '-state', state)
    wait_for(lambda: call(base, '/health')['status'] == 'ok')
    expect(reflected, 'drop', 'TCAM ACL drop')
    after = wait_for(lambda: call(base, f'/v1/nodes/{node_id}/program', token=OP))
    assert (after['policy_id'], after['version']) == (before['policy_id'], before['version'])
    assert [t['id'] for t in after['tunnels']] == [t['id'] for t in before['tunnels']]
    assert wait_for(lambda: call(base, '/v1/nodes', token=OP)[0]['status'] == 'ready')
    print('Everything on one node passed: stages, game filters, HTTP rules, classifiers, crafted '
          'packets, reflected CLDAP, GRE floods, reputation, on-demand mitigation, tunnels, BGP, '
          'sessions, provisioner, analytics and restart')
except BaseException:
    for index, log in enumerate(logs):
        log.seek(0); output = log.read().decode(errors='replace')
        if output: print(f'Process {index} log:\n{output[-5000:]}')
    raise
finally:
    for process in processes:
        if process.poll() is None:
            stop(process)
    for log in logs: log.close()
