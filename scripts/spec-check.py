#!/usr/bin/env python3
"""Check the OpenAPI specs against the code.

A spec that has drifted from the implementation is worse than no spec, so this
verifies three things: every $ref and security scheme resolves, every operation
declares a summary and responses, and the documented routes match the server's
dispatch switch in both directions.
"""
import yaml, re, sys
probs=[]
for f in ('api/openapi.yaml','api/node-openapi.yaml'):
    d=yaml.safe_load(open(f))
    schemas=d['components']['schemas']; defined=set(d['components']['securitySchemes'])
    used=set()
    def walk(o,w):
        if isinstance(o,dict):
            if '$ref' in o:
                n=o['$ref'].split('/')[-1]; used.add(n)
                if n not in schemas: probs.append(f"{f}: unresolved {o['$ref']}")
            for k,v in o.items():
                if k=='security':
                    for e in v or []:
                        for name in e:
                            if name not in defined: probs.append(f"{f}: unknown scheme {name} at {w}")
                walk(v,f"{w}.{k}")
        elif isinstance(o,list):
            for i,v in enumerate(o): walk(v,f"{w}[{i}]")
    walk(d,'root')
    changed=True
    while changed:
        changed=False
        for n in list(used):
            b=len(used); walk(schemas.get(n,{}),n)
            if len(used)!=b: changed=True
    for n in sorted(set(schemas)-used): probs.append(f"{f}: schema {n} never referenced")
    for path,ops in d['paths'].items():
        for meth,o in ops.items():
            if meth not in ('get','post','put','delete','patch'): continue
            if not o.get('summary'): probs.append(f"{f}: {meth} {path} has no summary")
            if not o.get('responses'): probs.append(f"{f}: {meth} {path} has no responses")
            if '{id}' in path and not any(p.get('name')=='id' for p in o.get('parameters',[])):
                probs.append(f"{f}: {meth} {path} missing id parameter")
    print(f"{f}: {len(d['paths'])} paths, {len(schemas)} schemas")

# The control plane spec must match the dispatch switch exactly.
src=open('internal/api/server.go').read()
b=src[src.index('func (s *Server) dispatch'):]; b=b[:b.index('\n}\n')]
code=set()
for l in b.split('\n'):
    if not l.startswith('\tcase '): continue
    m=re.search(r'Method(\w+)',l)
    if not m: continue
    p=re.search(r'path == "([^"]*)"',l); sp=re.search(r'hasSubpath\(path, "(\w+)", "(\w+)"\)',l)
    if p: code.add((m.group(1).lower(),'/v1/'+p.group(1)))
    elif sp: code.add((m.group(1).lower(),f"/v1/{sp.group(1)}/{{id}}/{sp.group(2)}"))
code |= {('get','/health'),('get','/metrics')}
d=yaml.safe_load(open('api/openapi.yaml'))
doc={(m,p) for p,ops in d['paths'].items() for m in ops if m in ('get','post','put','delete','patch')}
for i in sorted(code-doc): probs.append(f"in code but undocumented: {i[0].upper()} {i[1]}")
for i in sorted(doc-code): probs.append(f"documented but not in code: {i[0].upper()} {i[1]}")

# The agent spec must match the agent's mux.
agent=set(re.findall(r'mux\.HandleFunc\("(/\w*)"', open('cmd/scrub-node/main.go').read()))
nd=yaml.safe_load(open('api/node-openapi.yaml'))
for p in sorted(agent - set(nd['paths'])): probs.append(f"agent serves {p} but it is undocumented")
for p in sorted(set(nd['paths']) - agent): probs.append(f"agent spec documents {p} but it is not served")

if probs:
    print("\nPROBLEMS:"); [print("  -",x) for x in probs]; sys.exit(1)
print("both specs resolve, and every route matches the code")
