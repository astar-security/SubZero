# README

## cpe2cve

- Input : a inline CPE or a file with one CPE per line
- Doing : List every CVE (with severity, network exploitable, ...) associated to the given CPE 
- Output : stdout CSV result or export to CSV/PDF file

```
python3 cpe2cve_nist.py --file cpe_test.txt -o test.pdf
```

![image](https://github.com/astar-security/SubZero/assets/42293505/bf3a6c37-c779-427c-8a21-c59f064c8c74)

It used to obtain information about exploit availability from vulners, but it produce too many requests and need to reveal your CVE to vulners.
I also need to use the static local CPE dictionnary to avoid NIST API limitation.
