#!/usr/bin/python3

import sys

test = sys.argv[1].lower()
l = len(test)
poss = 2**l
comb = [bin(i)[2:].zfill(l) for i in range(poss)]

res = set()

for i in comb:
    res.add(''.join([ [test[c].upper(),test[c]][i[c] == '0'] for c in range(l) ]))

for i in res:
    print(i)

