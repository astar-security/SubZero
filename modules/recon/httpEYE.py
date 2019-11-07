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

def find_target(nmap, target):
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

def take_pic(target, path, distinguish):
    # Progression counter
    c = len(target)
    ind = 1
    print(f"[*] {c} targets to proceed")
    for t in target:
        print(t,target[t])

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
                try:
                    # Grab
                    filename = f"{path}/{ip}-{host}-{port[0]}_{mode}.png"
                    if ip == host:
                        filename = f"{path}/{ip}-{port[0]}_{mode}.png"
                    subprocess.run(['cutycapt', f"--url={url}", 
                        f"--out={filename}", 
                        '--out-format=png', '--insecure'], timeout=10)
                    print('[+] Success')
                except subprocess.TimeoutExpired:
                    print('[-] Timeout')
                    continue
        # Progression in %
        print(f"[*] Progress : {ind}/{c}")
        ind += 1

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
        print('[!] Given path does not exist')
        return 1
    nmap = ET.parse(args.NMAP_XML_FILE)
    target = {}
    find_target(nmap, target)
    take_pic(target, args.path, args.distinguish)

if __name__ == '__main__':
    main()

