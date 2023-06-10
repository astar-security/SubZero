# README

## nmap_summary

- Input: a NMAP XML result file
- Doing: organize data
- Output: stdout summury and JSON/XLSX capaibilities

```
python nmap_summary.py nmap_T_65k.xml
```

Useful for quickly get the UDP and TCP port to scan (the final summurize line).  
For example, if you already scanned the 65 535 TCp ports of an IP address, you can directly give this line to custom you Nessus policy or to perform a second nmap pass with script without rescanning everything.

The JSON and XLSX output are designed to be used by other Astar tools.

## Assetbeautifier

- Input: an asset in JSON format (see nmap_summary.py)
- Doing : nothing
- Output : terminal readable output

The tool is not resilient to missing data yet.
