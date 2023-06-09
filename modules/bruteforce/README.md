# README

## brutespray

- Input : a nmap XML file
- Doing : recognize services and bruteforce them
- Output : organized results files (one line per attempt) by service and by IP

```
python3 brutespray.py -L quick.login -P quick.password -s all NMAP_RESULT.xml
```

```
usage: bruteSpray.py [-h] [-w PATH] [-L LOGINS] [-P PASSWORDS]
                     [-s SERVICE]
                     NMAP_XML_FILE

Spread patator over a nmap result to bruteforce services

positional arguments:
  NMAP_XML_FILE  A nmap result file in xml format

options:
  -h, --help     show this help message and exit
  -w PATH        A path to store the results. Default is current folder
  -L LOGINS      A logins wordlist
  -P PASSWORDS   A passwords wordlist
  -s SERVICE     The service to attack. Default is all. Possible are :
                 ('ssh', 'snmp', 'vnc', 'mysql', 'mssql', 'telnet', 'ftp')
```
