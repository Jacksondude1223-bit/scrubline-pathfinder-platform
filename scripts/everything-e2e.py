"""Every feature a policy can turn on, on one node, through the real binaries: the policy in
configs/policy.everything.json deployed through scrub-api onto a scrub-node, traffic driven through
the node's own API, what the node renders read back and handed to the provisioner's dry run, and
the control plane restarted from its state with the node still at work."""
import base64
import json
import os
import pathlib
import socket
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
    for name, prefix in [('northwind', '203.0.113.0/24'), ('contoso', '198.51.100.0/24'),
                         ('fabrikam', '2001:db8:100::/48')]:
        token = call(base, f'/v1/tenants/{tenants[name]}/token', 'POST', OP, {})['token']
        def sees_only_its_own():
            rows = call(base, '/v1/analytics/overview', token=token)['prefixes']
            return [r['prefix'] for r in rows] == [prefix]
        wait_for(sees_only_its_own)

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
    print('Everything on one node passed: stages, game filters, HTTP rules, classifiers, '
          'reputation, on-demand mitigation, tunnels, BGP, sessions, provisioner, analytics and restart')
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
