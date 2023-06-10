#!/usr/bin/python3

import requests
import sys

if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
    print("Usage: ciphersuites.py CIPHERLIST\nWhere CIPHERLIST is a text file containing one cipher per line in IANA format")
    exit(0)

URL = "https://ciphersuite.info/api/cs"

cs = {}
r = requests.get(URL)
if r.ok:
    base = r.json()
    for c in base['ciphersuites']:
        for k, i in c.items():
            cs[k] = i
else:
    print(f"[!] Error during request to {URL}: {r.reason}")
    exit(1)

res = {}
with open(sys.argv[1]) as cipherlist:
    for cipher in map(str.strip, cipherlist.readlines()):
        s = cs[cipher]['security']
        if s not in res:
            res[s] = set()
        surname = cs[cipher]['openssl_name']
        res[s].add(surname if surname != '' else cipher)

for key in res:
    print("-- " + key.upper())
    for c in res[key]:
        print(c)








