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
import time

PROGRESS = 0
TOTAL = 0
lock = RLock()

class Cutycapt(Thread):

    def __init__(self, url, filename):
        Thread.__init__(self)
        self.url = url
        self.filename = filename

    def run(self):
        try:
            subprocess.run(['cutycapt', f"--url={self.url}",
                        f"--out={self.filename}",
                        '--out-format=png', '--insecure'], timeout=100)
            print(f"[+] {self.url} grabbing finished")
        except subprocess.TimeoutExpired:
            print(f"[-] {self.url} Timeout")
        with lock:
            global PROGRESS
            global TOTAL
            PROGRESS += 1
            print(f"[*] Progress: {PROGRESS}/{TOTAL}")

def find_target(nmap, target, distinguish):
    global TOTAL
    r = nmap.getroot()
    for host in r.iter("host"):
        if host.find("status").attrib["state"] == "up":
            for a in host.iter("address"):
                if a.get("addrtype") == "ipv4":
                    ip = a.get("addr")
                    if ip not in target:
                        target[ip] = {"hostnames":set(), "ports":set()}
                        target[ip]["hostnames"].add(ip)
                        # we assume that different hostnames don't lead to different open ports
                        for p in host.find("ports").iter('port'):
                            sname = p.find("service").get("name")
                            if sname == "https" or p.find("service").get("tunnel") == "ssl":
                                target[ip]["ports"].add((p.get("portid"),True))
                            elif sname == "http":
                                target[ip]["ports"].add((p.get("portid"),False))
                    for hostname in host.find("hostnames").iter("hostname"):
                        target[ip]["hostnames"].add(hostname.get("name"))
    if distinguish:
        for ip in target:
            TOTAL += len(target[ip]["hostnames"])*len(target[ip]["ports"])
    else:
        for ip in target:
            TOTAL += len(target[ip]["ports"])

def take_pic(target, path, distinguish):
    # Progression counter
    global TOTAL
    print(f"[*] {TOTAL} targets to proceed")
    for t in target:
        print(t,target[t])

    threads = []
    # for each host
    for ip in target:
        # for each hostname of the host
        for host in target[ip]["hostnames"]:
            if not distinguish and host is not ip:
                continue
            # for each ports of the host
            for port in target[ip]["ports"]:
                # is the port in http or https mode 
                mode = ["http","https"][port[1]]
                print(f"[*] Grabbing {host} on port {port[0]} with {mode}...")
                url = f"{mode}://{host}:{port[0]}"
                # Grab
                filename = f"{path}/{ip}-{host}-{port[0]}_{mode}.png"
                if ip == host:
                    filename = f"{path}/{ip}-{port[0]}_{mode}.png"
                threads.append(Cutycapt(url, filename))
    for t in threads:
        t.start()
        time.sleep(1)
    for t2 in threads:
        t2.join()

def main():
    parser = argparse.ArgumentParser(description='Spread cutycapt over a nmap '\
            'result to spot interresting Web interfaces.', add_help=True)
    parser.add_argument('-w', action="store", dest="path", default='.', 
            help='A path to store the pictures. Default is current folder')
    parser.add_argument('NMAP_XML_FILE', action="store",  
            help='A nmap result file in xml format')
    parser.add_argument('-d', '--distinguish', action="store_true",
            help="Capture for each hostname of the IP address", default=False)
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        try:
            subprocess.run(['mkdir', "-p", args.path])
        except Exception as e:
            print(f"[!] ERROR : {e}")
    nmap = ET.parse(args.NMAP_XML_FILE)
    target = {}
    find_target(nmap, target, args.distinguish)
    take_pic(target, args.path, args.distinguish)

if __name__ == '__main__':
    main()

