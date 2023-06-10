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

## mixedcase

- Input : a password (whatever the case)
- Doing : compute avery case variations
- Output : all the variations are printed to stdout

```
python3 mixedcase.py David
```
Dumb script to compute all the case variation of an input word.  
Useful if you cracked a LM hash and want to construct the possible candidates for cracking the NT version :
```
for i in $(cat test); do python3 mixedcase.py $i > wl; john --format=NT --wordlist=wl HASHDUMPFILE; done
```

## dns_dictionnary_asciize
 
- Input : a file with one word per line
- Doing : transform special character (é, à, ö, ...) to simple ascii (e, a, o)
- Output : a file (same name with _asciized_ extension) with the words transormed
 
 ```
 python3 dns_dictionnary_asciize.py WORDLIST.txt
 ```

Useful for subdomain enumeration through business context :
```
$ cewl -v -w wordlist_from_site.txt https://www.astar.org
$ python3 dns_dictionnary_asciize.py wordlist_from_site.txt
$ dnsenum astar.org -f wordlist_from_site.txt_asciized
```
