#!/usr/bin/env python3
"""Refresh the page's Content-Security-Policy connect-src from IANA's RDAP bootstrap files.
Usage: python3 tools/update-rdap-hosts.py   (run from the repository root; needs network access)
The browser may then talk only to data.iana.org and the RDAP servers IANA lists."""
import json, re, urllib.parse, urllib.request
hosts = set()
for kind in ('dns', 'ipv4', 'ipv6', 'asn'):
    with urllib.request.urlopen(f'https://data.iana.org/rdap/{kind}.json', timeout=30) as r:
        for svc in json.load(r)['services']:
            for u in svc[1]:
                p = urllib.parse.urlparse(u)
                if p.scheme == 'https' and p.hostname: hosts.add(p.hostname)
src = ' '.join(['https://data.iana.org'] + [f'https://{h}' for h in sorted(hosts)])
path = 'site/index.html'; page = open(path).read()
page, n = re.subn(r'connect-src [^;]*;', f'connect-src {src};', page, count=1)
assert n == 1, 'no connect-src found'
open(path, 'w').write(page)
print(f'{len(hosts)} RDAP hosts written to {path}')
