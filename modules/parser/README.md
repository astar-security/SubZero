# README

## nmap2asset

- Input: a NMAP XML result file
- Doing: organize data into json files
- Output: stdout summurize and json files desgined to be imported in a third party tool

```
python nmap2asset.py nmap_T_65k.xml
```

Useful for quickly get the UDP and TCP port to scan (the final summurize line).  
For example, if you already scanned the 65 535 TCp ports of an IP address, you can directly give this line to custom you Nessus policy or to perform a second nmap pass with script without rescanning everything.
