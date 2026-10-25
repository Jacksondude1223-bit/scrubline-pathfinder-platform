"""Exercise Rust API/node/traffic processes, authorization, persistence and failover."""
import base64
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / os.environ.get('PATHFINDER_BIN_DIR', 'target/debug')
ENV = dict(os.environ, SCRUBLINE_API_TOKEN='integration-operator',
           SCRUBLINE_ENROLL_TOKEN='integration-enroll',
           SCRUBLINE_NODE_API_TOKEN='integration-node-local')
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
    if process.poll() is None:
        process.terminate(); process.wait(timeout=15)

def call(base, path, method='GET', token=None, data=None, expected=200, context=None):
    headers = {}
    if token is not None: headers['Authorization'] = 'Bearer ' + token
    raw = None if data is None else json.dumps(data).encode()
    if raw is not None: headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(base + path, data=raw, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=10, context=context)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(); status = response.status
        assert status == expected, (method, path, status, expected, body[:500])
        if 'application/json' in response.headers.get('Content-Type', ''):
            return json.loads(body)
        return body.decode()

def wait_for(check, seconds=15):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            result = check()
            if result: return result
        except (OSError, AssertionError, KeyError, ValueError) as error:
            last = error
        time.sleep(0.1)
    raise AssertionError(('timed out waiting for condition', last))

OP = ENV['SCRUBLINE_API_TOKEN']; ENROLL = ENV['SCRUBLINE_ENROLL_TOKEN']
LOCAL = ENV['SCRUBLINE_NODE_API_TOKEN']
with tempfile.TemporaryDirectory() as temporary:
    temporary = pathlib.Path(temporary)
    try:
        api_port = port(); base = f'http://127.0.0.1:{api_port}'
        state = temporary / 'state.json'
        api = start('scrub-api', '-addr', f'127.0.0.1:{api_port}', '-state', state)
        wait_for(lambda: call(base, '/health')['status'] == 'ok')
        call(base, '/v1/nodes', expected=401)
        call(base, '/v1/fabric', token=ENROLL, expected=403)
        registration = call(base, '/v1/nodes/register', 'POST', ENROLL,
                            {'name':'manual', 'region':'us', 'capacity_gbps':100,
                             'advertise':'192.0.2.1:9091', 'tunnel_src':'192.0.2.1'})
        node_id = registration['node']['id']; node_token = registration['token']
        second = call(base, '/v1/nodes/register', 'POST', ENROLL,
                      {'name':'manual-2', 'region':'de', 'capacity_gbps':50,
                       'tunnel_src':'192.0.2.2'})
        other_id = second['node']['id']
        call(base, f'/v1/nodes/{other_id}/program', token=node_token, expected=403)
        call(base, f'/v1/nodes/{other_id}/heartbeat', 'POST', node_token, {}, expected=403)
        call(base, '/v1/policies', 'POST', node_token, {}, expected=403)
        call(base, '/v1/nodes/register', 'POST', ENROLL,
             {'name':'manual', 'region':'us', 'advertise':'192.0.2.99:9091'}, expected=409)
        policy = {'id':'runtime-test', 'name':'runtime',
                  'protected':['203.0.113.0/24','198.51.100.0/24'],
                  'rules':[{'id':'dns', 'stage':'asic', 'action':'drop',
                            'match':{'sport':53}},
                           {'id':'inspect', 'stage':'zc', 'action':'inspect',
                            'pps':1000000, 'match':{}}],
                  'games':[{'id':'a2s', 'profile':'a2s', 'dport':27015, 'proto':'udp'},
                           # HTTP on a game server's own port, held to its rules.
                           {'id':'web', 'dst_cidr':'203.0.113.20/32', 'dport':30120,
                            'http':{'default':'drop',
                                    'paths':[{'path':'/players.json', 'rate_per_source':1}]}}],
                  'tunnels':[{'id':'customer', 'prefixes':['203.0.113.0/24'],
                              'remote':'192.0.2.100', 'required':True}],
                  'reputation':{'fast_pass':'challenge','penalty_box':True}}
        bad_http = dict(policy['games'][1], http={'default':'block'})
        call(base, '/v1/policies', 'POST', OP,
             dict(policy, games=[policy['games'][0], bad_http]), expected=400)
        for bad_rule in [dict(policy['rules'][1], action='count'),
                         dict(policy['rules'][1], stage='asic', action='rate_limit'),
                         dict(policy['rules'][1], pps=-1),
                         dict(policy['rules'][1], match={'dport':65536})]:
            call(base, '/v1/policies', 'POST', OP,
                 dict(policy, rules=[bad_rule]), expected=400)
        saved = call(base, '/v1/policies', 'POST', OP, policy)
        assert saved['challenge_secret']
        call(base, '/v1/policies/runtime-test/deploy', 'POST', OP, {})
        assert call(base, f'/v1/nodes/{node_id}/program', token=node_token)['version'] == 1
        call(base, '/v1/nodes/unknown/program', token=OP, expected=404)
        call(base, '/v1/does-not-exist', token=OP, expected=404)
        call(base, '/v1/v1/nodes', token=OP, expected=404)
        node_port = port(); local = f'http://127.0.0.1:{node_port}'
        node = start('scrub-node', '-api', base, '-listen', f'127.0.0.1:{node_port}',
                     '-name','runtime-node','-region','us','-capacity','100',
                     '-capacity-pps','1000000','-local-as','64512',
                     '-tunnel-src','192.0.2.3')
        health = wait_for(lambda: call(local, '/health'))
        runtime_id = health['node']
        wait_for(lambda: call(local, '/bgp', token=LOCAL)['announcements'])
        call(local, '/bgp', expected=401)
        call(local, '/decide', token=LOCAL, expected=405)
        call(local, '/sessions?format=bird', token=LOCAL)
        call(local, '/tunnels?format=iproute2', token=LOCAL)
        # The operator moves this node's tunnels onto an address of its own; the agent picks it
        # up from its program and builds the tunnel, and the reply path, from there.
        endpoint = f'/v1/nodes/{runtime_id}/tunnel-endpoint'
        call(base, endpoint, 'PUT', node_token, {'address':'192.0.2.30'}, expected=403)
        call(base, endpoint, 'PUT', OP, {'address':'192.0.2.2'}, expected=409)
        assert call(base, endpoint, 'PUT', OP, {'address':'192.0.2.30'})['tunnel_src'] == '192.0.2.30'
        rendered = wait_for(lambda: (lambda text: 'local 192.0.2.30 ' in text and text)(
            call(local, '/tunnels?format=iproute2', token=LOCAL)))
        assert 'iifname "scr-customer" ip saddr != { 203.0.113.0/24 } drop' in rendered, rendered
        rows = call(base, '/v1/tunnels', token=OP)['tunnels'][0]['nodes']
        assert any(r['node_id'] == runtime_id and r['endpoint'] == '192.0.2.30'
                   and r['endpoint_assigned'] for r in rows), rows
        # The clean traffic down the tunnel is capped, never more than 2.5 Gbit/s in total, and
        # the agent shapes to its share of whatever the operator allocates.
        call(base, '/v1/tunnels/customer/rate', 'PUT', OP, {'rate_mbps':2501}, expected=400)
        assert call(base, '/v1/tunnels/customer/rate', 'PUT', OP,
                    {'rate_mbps':100})['tunnel']['rate_mbps'] == 100
        def shaped(text):
            rates = [int(line.split(' rate ')[1].split('kbit')[0]) for line in text.splitlines()
                     if line.startswith('tc qdisc replace dev scr-customer root tbf rate ')]
            return rates and 0 < rates[0] <= 100000 and text
        wait_for(lambda: shaped(call(local, '/tunnels?format=iproute2', token=LOCAL)))
        # The panel pins the customer's tunnel to this node, which then holds the whole
        # allowance; the provisioner, dry-run, shows what it would put on the box for it.
        call(base, '/v1/tunnels/customer/location', 'PUT', OP, {'node':'node-none'}, expected=400)
        pinned = call(base, '/v1/tunnels/customer/location', 'PUT', OP, {'node':runtime_id})
        assert pinned['tunnel']['node'] == runtime_id, pinned
        def provisioned():
            run = subprocess.run([str(BIN / 'scrub-provision'), '-agent', local, '-once', '-dry-run'],
                                 cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=30)
            return run.returncode == 0 and 'tbf rate 100000kbit' in run.stdout and run.stdout
        planned = wait_for(provisioned)
        assert 'ip link add scr-customer type gre local 192.0.2.30 remote 192.0.2.100' in planned, planned
        assert 'add rule inet scrubline input meta l4proto { 47, 4 } ip saddr != {' in planned, planned
        call(local, '/tunnels', 'POST', LOCAL,
             {'tunnels':[{'tunnel_id':'customer','state':'up'}]})
        wait_for(lambda: any(a['node_id']==runtime_id and a['state']=='announce'
                             and a['prefix']=='203.0.113.0/24'
                             for a in call(base, '/v1/fabric', token=OP)['announcements']))
        flow = {'src_ip':'192.0.2.9','dst_ip':'203.0.113.10','proto':'udp',
                'sport':12345,'dport':27015,'pps':1,
                'payload':base64.b64encode(bytes([255]*4)+b'T').decode()}
        challenged = call(local, '/decide', 'POST', LOCAL, flow)
        assert challenged['action']=='challenge', challenged
        cookie = base64.b64decode(challenged['reply'])[5:]
        echoed = dict(flow, payload=base64.b64encode(bytes([255]*4)+b'T'+cookie).decode())
        assert call(local, '/decide', 'POST', LOCAL, echoed)['action']=='permit'
        assert call(local, '/decide', 'POST', LOCAL, echoed)['reason']=='verified source, fast path'
        assert call(local, '/decide', 'POST', LOCAL, dict(flow,sport=53))['stage']=='asic'
        invalid = dict(flow, src_ip='192.0.2.88', payload='AA==')
        for _ in range(4): call(local, '/decide', 'POST', LOCAL, invalid)
        assert call(local, '/decide', 'POST', LOCAL, invalid)['reason']=='source is in the penalty box'
        assert call(local, '/reputation', 'POST', LOCAL, {'release':['192.0.2.88']})['released']==1
        # On demand, the node only watches the customer's traffic until it reaches the tunnel's
        # thresholds, and filters it from then on; the control plane hears of it at once.
        call(base, '/v1/tunnels/customer/mitigation', 'PUT', OP, {'mitigation':'on_demand','attack_pps':5000})
        wait_for(lambda: call(local, '/tunnels', token=LOCAL)['tunnels'][0].get('mitigation')=='on_demand')
        reflected = dict(flow, src_ip='198.51.100.70', sport=53)
        idle = call(local, '/decide', 'POST', LOCAL, reflected)
        assert idle['action']=='permit' and idle['reason'].startswith('watching only'), idle
        flooded = call(local, '/decide', 'POST', LOCAL, dict(reflected, pps=6000))
        assert flooded['action']=='drop' and flooded['stage']=='asic', flooded
        def mitigating():
            rows = call(base, '/v1/tunnels', token=OP)['tunnels'][0]['nodes']
            return [r for r in rows if r['node_id']==runtime_id and r.get('mitigating')]
        assert wait_for(mitigating, seconds=5)[0]['mitigating_since']
        call(base, '/v1/tunnels/customer/mitigation', 'PUT', OP, {'mitigation':'always'})
        wait_for(lambda: 'mitigation' not in call(local, '/tunnels', token=LOCAL)['tunnels'][0])
        def request(src, path, pps=1):
            raw = f'GET {path} HTTP/1.1\r\nHost: 203.0.113.20:30120\r\n\r\n'.encode()
            return dict(flow, src_ip=src, dst_ip='203.0.113.20', proto='tcp', dport=30120,
                        pps=pps, payload=base64.b64encode(raw).decode())
        assert call(local, '/decide', 'POST', LOCAL, request('192.0.2.50', '/players.json'))['action']=='permit'
        limited = call(local, '/decide', 'POST', LOCAL, request('192.0.2.50', '/players.json', pps=5))
        assert limited['action']=='drop' and limited['filter']=='web', limited
        assert limited['reason'].endswith('/players.json: more than 1 request a second to this path from this source'), limited
        unlisted = call(local, '/decide', 'POST', LOCAL, request('192.0.2.51', '/%2E%2E/secret'))
        assert unlisted['reason'].endswith('GET /secret: not a path this server allows'), unlisted
        call(local, '/reputation?limit=5', token=LOCAL)
        for _ in range(3):
            call(local, '/egress','POST',LOCAL,
                 {'src_ip':'203.0.113.10','dst_ip':'192.0.2.10','proto':'udp','pps':4})
            time.sleep(0.26)
        for i in range(3):
            call(local, '/decide','POST',LOCAL,
                 dict(flow,src_ip=f'192.0.2.{100+i}',sport=53,pps=100000))
        tenant = call(base, '/v1/tenants', 'POST', OP,
                      {'id':'customer-a','name':'Customer A','prefixes':['203.0.113.0/24']})
        tenant_token = call(base, '/v1/tenants/customer-a/token','POST',OP,{})['token']
        call(base,'/v1/nodes',token=tenant_token,expected=403)
        call(base,'/v1/analytics/series?prefix=198.51.100.0/24',token=tenant_token,expected=403)
        call(base,'/v1/analytics/events?prefix=198.51.100.0/24',token=tenant_token,expected=403)
        wait_for(lambda: call(base,'/v1/analytics/overview',token=tenant_token)['prefixes'][0]['offered']>0)
        overview = call(base,'/v1/analytics/overview?window=1h',token=tenant_token)
        assert all(p['prefix']=='203.0.113.0/24' for p in overview['prefixes'])
        call(base,'/v1/analytics/series?prefix=203.0.113.0/24&window=1h&step=5m',token=tenant_token)
        # The flood reaches analytics with the node's next heartbeat.
        wait_for(lambda:call(base,'/v1/analytics/events?prefix=203.0.113.0/24',token=tenant_token)['events'])
        rotated = call(base, '/v1/tenants/customer-a/token','POST',OP,{})['token']
        call(base,'/v1/analytics/overview',token=tenant_token,expected=401)
        tenant_token = rotated
        samples=json.loads((ROOT/'configs/ml.samples.json').read_text())
        call(base,'/v1/ml/samples','POST',OP,samples)
        model=call(base,'/v1/ml/train','POST',OP,{'epochs':30,'lr':0.2,'threshold':0.65})
        assert model['ready'] and model['http']['ready'], model
        call(base,'/v1/ml/score','POST',OP,dict(flow,payload=''))
        call(base,'/v1/ml/model',token=node_token)
        wait_for(lambda:call(base,f'/v1/nodes/{runtime_id}/stats',token=OP)['stats']['ml']['ready'])
        # The node installs the request model with the flow model, and the HTTP rules hand it what
        # they allow: a game client's request passes, and one shaped like the flood samples, which
        # no rule refuses, is dropped by it.
        def http_flow(src, raw):
            return dict(flow, src_ip=src, dst_ip='203.0.113.20', proto='tcp', dport=30120, pps=1,
                        payload=base64.b64encode(raw).decode())
        client=http_flow('192.0.2.77', b'GET /players.json HTTP/1.1\r\nHost: 203.0.113.20:30120\r\n'
                         b'User-Agent: CitizenFX/1\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n')
        assert call(local,'/decide','POST',LOCAL,client)['action']=='permit'
        flooding=http_flow('192.0.2.78', b'GET /players.json?_=3c9e HTTP/1.0\r\n\r\n')
        judged=call(local,'/decide','POST',LOCAL,flooding)
        assert judged['action']=='drop' and 'by the request model' in judged['reason'], judged
        assert call(local,'/metrics',token=LOCAL).count('scrubline_ml_http_drops_total{')==1
        call(base,'/v1/ml/model','DELETE',OP)
        wait_for(lambda:not call(base,f'/v1/nodes/{runtime_id}/stats',token=OP)['stats']['ml']['ready'])
        metrics=call(base,'/metrics',token=OP)
        assert 'scrubline_api_requests_total' in metrics and 'scrubline_prefix_offered_total' in metrics
        call(base,'/metrics',token=node_token,expected=403)
        node_metrics = call(local,'/metrics',token=LOCAL)
        assert 'scrubline_game_http_rate_limited_total{' in node_metrics, node_metrics
        traffic=start('scrub-traffic','-nodes',local,'-interval','50ms','-seed','42')
        time.sleep(1); assert traffic.poll() is None; stop(traffic)
        snapshot=call(base,'/v1/state',token=OP)
        raw=state.read_text()
        assert node_token not in raw and tenant_token not in raw
        assert snapshot['last_policy_id']=='runtime-test'
        assert state.stat().st_mode & 0o777 == 0o600
        call(local,'/tunnels','POST',LOCAL,{'tunnels':[{'tunnel_id':'customer','state':'down'}]})
        wait_for(lambda: any(a['node_id']==runtime_id and a['state']=='withdraw'
                             and 'down' in a['reason']
                             for a in call(base,'/v1/fabric',token=OP)['announcements']))
        # A request for a node's program waits at the control plane for the next one; stopping
        # answers it rather than holding up the shutdown until it times out.
        held=call(base,f'/v1/nodes/{runtime_id}/program',token=OP)['compiled_at']
        answered=[]
        waiter=threading.Thread(target=lambda:answered.append(call(
            base,f'/v1/nodes/{runtime_id}/program?wait=30s&since={held}',token=OP)))
        waiter.start(); time.sleep(0.5)
        stopping=time.monotonic(); stop(api)
        assert time.monotonic()-stopping<5, 'a held request delayed the shutdown'
        waiter.join(); assert answered and answered[0]['compiled_at']==held, answered
        api=start('scrub-api','-addr',f'127.0.0.1:{api_port}','-state',state)
        wait_for(lambda:call(base,'/health'))
        assert call(base,'/v1/tenants',token=OP)[0]['id']==tenant['id']
        call(base,'/v1/analytics/overview',token=tenant_token)
        wait_for(lambda:call(base,f'/v1/nodes/{runtime_id}/program',token=OP))
        replica_port=port();replica_url=f'http://127.0.0.1:{replica_port}'
        replica=start('scrub-api','-addr',f'127.0.0.1:{replica_port}',
                      '-role','replica','-primary',base,'-follow-interval','300ms',
                      '-state',temporary/'replica.json')
        wait_for(lambda:call(replica_url,'/v1/tenants',token=OP))
        call(replica_url,'/v1/policies','POST',OP,policy,expected=409)
        # Fence the primary before promoting its replica.
        stop(api)
        assert call(replica_url,'/v1/promote','POST',OP,{})['mode']=='primary'
        call(replica_url,'/v1/promote','POST',OP,{},expected=409)
        call(replica_url,'/v1/analytics/overview',token=tenant_token)
        call(replica_url,'/v1/tenants/customer-a','DELETE',OP)
        call(replica_url,'/v1/analytics/overview',token=tenant_token,expected=401)
        stop(node);stop(replica)
        certs=temporary/'certs'
        subprocess.run(['sh','scripts/gen-dev-certs.sh','-dir',str(certs)],cwd=ROOT,check=True)
        tls_port=port();tls=f'https://127.0.0.1:{tls_port}'
        secure=start('scrub-api','-addr',f'127.0.0.1:{tls_port}',
                     '-tls-cert',certs/'server.pem','-tls-key',certs/'server-key.pem')
        context=ssl.create_default_context(cafile=str(certs/'ca.pem'))
        wait_for(lambda:call(tls,'/health',context=context))
        try:
            call(tls,'/health')
        except urllib.error.URLError: pass
        else: raise AssertionError('untrusted TLS certificate was accepted')
        subprocess.run([str(BIN/'scrubctl'),'-api',tls,'-ca',str(certs/'ca.pem'),'nodes'],env=ENV,check=True,stdout=subprocess.DEVNULL)
        stop(secure)
        refused=start('scrub-api','-addr','0.0.0.0:0')
        assert refused.wait(timeout=5)!=0
        print('Rust runtime E2E passed: API, node, traffic, roles, challenges, analytics, persistence, replica promotion and TLS')
    except BaseException:
        for index,log in enumerate(logs):
            log.seek(0); output=log.read().decode(errors='replace')
            if output: print(f'Process {index} log:\n{output[-5000:]}')
        raise
    finally:
        for process in processes:stop(process)
        for log in logs:log.close()
