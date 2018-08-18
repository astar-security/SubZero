# SubZero
A free and open source vulnerability scanner based on python

Pentesters do not like NASL (and shit they're right). Today, everyone (ok ok...many people) want to script in python.
OpenVas is currently far away from Nessus because its community is not as huge as possible... and I think it's because of NASL

Here, I propose to replace OpenVas with a better scanner, written in python for python exploits with python lovers.

The main step are defined as:
1) create an universal vulnerability descriptor
1) create an universal exploit plugin template
2) create or use existing fingerprinters (TCP/UDP services, OS, framework, etc.) and associate with the CPE database
3) correlate with known vulnerabilities on these CPE (with a database like vulners) and associate with CVE and the others
4) discover vulnerabilities without correlation by using effective exploits
5) discover vulnerabilties based on configuration flaws (default password, TLS not enabled, telnet present, etc.)

The extended features will be:
1) a web crawler and a web intrusion engine wich associate flaws with CWE database (even if arachni and burp are so sweet)
2) a network protocol scanner for detecting poor protocols (Netbios, LLMNR, ARP) and try some attacks
3) a wifi scanner and attacker
4) a complete active directory configuration scanner
5) be able to attack modern infrastructures: docker (especially vulnerable intermediate layers), AWS, Azure, etc.

Feel free to contact me at contact[at}astar{dot]services
