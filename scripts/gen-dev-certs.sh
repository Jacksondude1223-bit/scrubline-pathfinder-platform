#!/bin/sh
set -eu
python3 - "$@" <<'PY'
import argparse,ipaddress,pathlib,subprocess,tempfile,os
p=argparse.ArgumentParser(description='Generate a local development CA and server certificate')
p.add_argument('-dir','--dir',default='certs');p.add_argument('-host','--host',default='127.0.0.1,localhost');p.add_argument('-days','--days',type=int,default=90)
a=p.parse_args()
if a.days<=0:p.error('days must be positive')
d=pathlib.Path(a.dir);d.mkdir(mode=0o700,parents=True,exist_ok=True)
sans=[]
for host in a.host.split(','):
    host=host.strip()
    if not host:continue
    try:ipaddress.ip_address(host);kind='IP'
    except ValueError:
        if not all(c.isalnum() or c in '.-*' for c in host):p.error('invalid certificate hostname')
        kind='DNS'
    sans.append(f'{kind}:{host}')
if not sans:p.error('at least one host is required')
def run(*args):subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
with tempfile.TemporaryDirectory() as scratch:
    temp=pathlib.Path(scratch)
    ca=temp/'ca-key.pem';csr=temp/'server.csr';ext=temp/'server.ext'
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName='+','.join(sans)+'\n')
    run('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(ca),'-out',str(d/'ca.pem'),'-days',str(a.days),'-subj','/CN=scrubline dev CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,digitalSignature')
    run('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(d/'server-key.pem'),'-out',str(csr),'-subj','/CN=scrubline')
    os.chmod(d/'server-key.pem',0o600)
    run('x509','-req','-in',str(csr),'-CA',str(d/'ca.pem'),'-CAkey',str(ca),'-CAserial',str(temp/'serial'),'-CAcreateserial','-out',str(d/'server.pem'),'-days',str(a.days),'-extfile',str(ext))
print(f'Wrote {d}/ca.pem, server.pem, and server-key.pem')
PY
