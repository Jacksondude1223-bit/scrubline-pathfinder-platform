#!/usr/bin/env python3
"""Check the OpenAPI specs against the code.

A spec that has drifted from the implementation is worse than no spec, so this
verifies three things: every $ref and security scheme resolves, every operation
declares a summary and responses, and the documented routes match the server's
dispatch switch in both directions.
"""
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("spec-check needs PyYAML: python3 -m pip install PyYAML")

probs = []
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

# Read literal route patterns from the Rust dispatch match.
src=open('src/api.rs').read()
src=src[src.index('fn dispatch('):src.index('pub fn router(')]
code=set()
for method,terms in re.findall(r'\(\s*"(GET|POST|PUT|DELETE|PATCH)"\s*,\s*\[([^\]]+)\]\s*,?\s*\)',src):
    parts=[part.strip() for part in terms.split(',') if part.strip()]
    if any(part not in ('_',) and not part.startswith('"') for part in parts):
        continue
    path='/v1/'+'/'.join('{id}' if part=='_' else part.strip('"') for part in parts)
    code.add((method.lower(),path))
for operations in re.findall(r'\("GET",\s*\["analytics",\s*kind\]\)\s*if\s*\[([^\]]+)\]\.contains\(kind\)',src):
    for leaf in re.findall(r'"([^" ]+)"',operations):
        code.add(('get','/v1/analytics/'+leaf))
code|={('get','/health'),('get','/metrics')}
d=yaml.safe_load(open('api/openapi.yaml'))
doc={(m,p) for p,ops in d['paths'].items() for m in ops if m in ('get','post','put','delete','patch')}
for i in sorted(code-doc): probs.append(f"in Rust but undocumented: {i[0].upper()} {i[1]}")
for i in sorted(doc-code): probs.append(f"documented but not in Rust: {i[0].upper()} {i[1]}")
agent=set(re.findall(r'\.route\("(/\w*)"',open('src/node.rs').read()))
nd=yaml.safe_load(open('api/node-openapi.yaml'))
for p in sorted(agent-set(nd['paths'])): probs.append(f"agent serves {p} but it is undocumented")
for p in sorted(set(nd['paths'])-agent): probs.append(f"agent spec documents {p} but it is not served")
# Every setting the catalog lists is documented where a policy holds it.
section_schema={'':'Policy','crafted':'CraftedPolicy','reflection':'ReflectionPolicy',
    'reflection.custom[]':'CustomVector','protocols':'ProtocolPolicy','ack_flood':'AckFloodPolicy',
    'syn_flood':'SynFloodPolicy','fragments':'FragmentPolicy','icmp':'IcmpPolicy',
    'aggregation':'AggregationPolicy','reputation':'ReputationPolicy','egress':'EgressPolicy',
    'pulse':'PulsePolicy','mitigation':'MitigationPolicy','ml':'MlPolicy','games[]':'GameFilter',
    'games[].http':'GameHttp','games[].http.slow':'GameHttpSlow','rules[]':'Rule',
    'rules[].match':'Match','profiles[]':'Profile'}
catalog=open('src/tuning.rs').read()
catalog=catalog[catalog.index('pub static SETTINGS'):]
catalog=catalog[:catalog.index('\n];')]
settings=re.findall(r'\b(?:num|numz|frac|choice|flag|list|map|text)\(\s*"([^"]+)"',catalog)
if len(settings)<100: probs.append(f"read only {len(settings)} settings from src/tuning.rs")
schemas=d['components']['schemas']
for path in settings:
    section,_,leaf=path.rpartition('.')
    schema=section_schema.get(section)
    if schema is None:
        probs.append(f"setting {path} belongs to no schema spec-check knows"); continue
    if leaf.removesuffix('[]') not in schemas.get(schema,{}).get('properties',{}):
        probs.append(f"setting {path} is not documented in {schema}")
if probs:
    print("\nPROBLEMS:")
    for problem in probs:print('  -',problem)
    sys.exit(1)
print(f'both specs resolve, every route matches the Rust implementation, and all {len(settings)} settings are documented')
