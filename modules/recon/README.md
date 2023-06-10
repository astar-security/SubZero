# README

## HTTPEye

- Input : a NMAP XML result file
- Doing : take a screenshot of every HTTP service recognized
- Output : the screenshots are saved as individual pictures (their name stipulates the IP and the port)

```
python3 httpeye.py NMAP_RESULT.XML
```

```
usage: httpEYE.py [-h] [-w PATH] [-d] NMAP_XML_FILE

Spread cutycapt over a nmap result to spot interresting Web interfaces.

positional arguments:
  NMAP_XML_FILE      A nmap result file in xml format

options:
  -h, --help         show this help message and exit
  -w PATH            A path to store the pictures. Default is current
                     folder
  -d, --distinguish  Capture for each hostname of the IP address
```

Very useful in coporate network engagement to quickly spot unprotected web interfaces even if they are not on common HTTP ports (80 and 443). To achieve this, you need to have run your nmap with "-sV" option to let it recognize HTTP service on uncommon ports.
