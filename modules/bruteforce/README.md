# README

## brutespray

- Input : a nmap XML file
- Doing : recognize services and bruteforce them
- Output : organized results files (one line per attempt) by service and by IP

```
python3 brutespray.py -L quick.login -P quick.password -s all NMAP_RESULT.xml
```
