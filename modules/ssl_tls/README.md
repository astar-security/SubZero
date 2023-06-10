# README

## ciphersuites

- Input: a file with one ciphersuite per line (in the IANA format)
- Doing: ask to ciphersuite.info API which ciphersuites are secure or not
- Output: stdout list of the ciphersuite (in openssl format name) categorized by robustness

```
python3 ciphersuites.py CIPHERLIST.txt
```
