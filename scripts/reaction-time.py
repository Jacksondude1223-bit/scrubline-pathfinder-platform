"""Time how fast the fabric answers a flood, from the first packets a node sees to another node
announcing the customer pinned to it and the node padding its own route, all before BGP."""
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
ENV = dict(os.environ, SCRUBLINE_API_TOKEN='reaction-operator',
           SCRUBLINE_ENROLL_TOKEN='reaction-enroll',
           SCRUBLINE_NODE_API_TOKEN='reaction-node-local')
OP = ENV['SCRUBLINE_API_TOKEN']; LOCAL = ENV['SCRUBLINE_NODE_API_TOKEN']
# What the fabric has to do it in. Polling for instructions alone took up to two seconds.
LIMIT = float(os.environ.get('REACTION_LIMIT_SECONDS', '1'))
PREFIX = '203.0.113.0/24'
CAPACITY = 100000
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

def call(base, path, method='GET', token=None, data=None):
    headers = {}
    if token is not None: headers['Authorization'] = 'Bearer ' + token
    raw = None if data is None else json.dumps(data).encode()
    if raw is not None: headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(base + path, data=raw, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())

def wait_for(check, seconds=15, every=0.1):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            result = check()
            if result: return result
        except (OSError, AssertionError, KeyError, ValueError) as error:
            last = error
        time.sleep(every)
    raise AssertionError(('timed out waiting for condition', last))

def route(local):
    """What a node's agent has its BGP speaker announce for the customer's prefix."""
    rows = call(local, '/bgp', token=LOCAL)['announcements'] or []
    return next((r for r in rows if r['prefix'] == PREFIX), {})

try:
    api_port = port(); base = f'http://127.0.0.1:{api_port}'
    start('scrub-api', '-addr', f'127.0.0.1:{api_port}')
    wait_for(lambda: call(base, '/health')['status'] == 'ok')
    nodes = []
    for name, src in [('lhr-1', '192.0.2.11'), ('lhr-2', '192.0.2.12')]:
        local = f'http://127.0.0.1:{port()}'
        start('scrub-node', '-api', base, '-listen', local.removeprefix('http://'),
              '-name', name, '-region', 'lhr', '-capacity-pps', CAPACITY,
              '-local-as', 64512, '-tunnel-src', src)
        nodes.append((local, wait_for(lambda: call(local, '/health'))['node']))
    (location, location_id), (helper, _) = nodes
    policy = {'id': 'reaction', 'name': 'reaction', 'protected': [PREFIX],
              'tunnels': [{'id': 'northwind', 'remote': '198.18.0.9', 'prefixes': [PREFIX],
                           'node': location_id}]}
    call(base, '/v1/policies', 'POST', OP, policy)
    call(base, '/v1/policies/reaction/deploy', 'POST', OP, {})
    # The customer's location announces them, and the other node stands by.
    wait_for(lambda: route(location).get('state') == 'announce'
             and route(helper).get('state') == 'withdraw')
    # Then a flood at 90% of what the location takes. Its ten-second mean stays at a tenth of
    # that, far below the 80% at which the fabric helps; the last second's rate is the whole of it.
    flow = {'src_ip': '198.51.100.7', 'dst_ip': '203.0.113.10', 'proto': 'udp',
            'dport': 27015, 'pps': CAPACITY // 10}
    started = time.monotonic()
    for _ in range(9):
        call(location, '/decide', 'POST', LOCAL, flow)
    flooded = time.monotonic() - started
    helping = wait_for(lambda: route(helper).get('state') == 'announce' and time.monotonic(),
                       seconds=10, every=0.005) - started
    padded = wait_for(lambda: route(location).get('prepends', 0) >= 1 and time.monotonic(),
                      seconds=10, every=0.005) - started
    print(f'Flood sent in {flooded * 1000:.0f} ms; the other node announced the customer after '
          f'{helping * 1000:.0f} ms, and the location padded its route after {padded * 1000:.0f} ms')
    reason = route(helper)['reason']
    assert reason.startswith('overflow for lhr-1:'), reason
    assert max(helping, padded) < LIMIT, f'the fabric took longer than {LIMIT}s to react'
except BaseException:
    for index, log in enumerate(logs):
        log.seek(0); output = log.read().decode(errors='replace')
        if output: print(f'Process {index} log:\n{output[-5000:]}')
    raise
finally:
    for process in processes:
        if process.poll() is None:
            process.terminate(); process.wait(timeout=15)
    for log in logs: log.close()
