#!/usr/bin/python3

"""
Part of SubZero project: 
Written by David SORIA (Sibwara, dsoria@astar.org) in 2025 and chatgpt (a little)
Do not sell in a commercial package
"""

import logging
import socket
import ipaddress
from scapy.all import ARP, Ether, srp, IP, sr1, ICMP, TCP, UDP
from impacket.nmb import NetBIOS 
from threading import Thread, RLock
import argparse

RESULT = {}
LOCK = RLock()
TCP_PING_PORTS = (22, 80, 135, 445)
UDP_PING_PORTS = (46236)

#########
# UTILS #
#########

def to_avoid(ip):
    if ip.split('.')[-1] in ('0', '255'):
        return True
    else:
        return False

#####################
# DETECTION METHODS #
#####################

def DNS_Lookup(ip, outfile, timeout):
    global RESULT
    global LOCK
    try:
        hostname = socket.gethostbyaddr(ip)
        logging.debug(f"[*] DNS resolution for {ip} leads to {hostname}")
        if hostname[0]:
            with LOCK:
                RESULT[ip]['state'] = 'alive'
                RESULT[ip]['method'] = 'dns'
                RESULT[ip]['dns'] = hostname [0]
                outfile.write(ip + '\n')
                print(f"Salut {ip} ({hostname[0]}), ça fart ?")
    except Exception as e:
        logging.debug(f"[!] DNS resolution for {ip} failed due to {e}")

def ARP_Lookup(ip, outfile, timeout):
    global RESULT
    global LOCK
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        mac = srp(packet, timeout=timeout, verbose=0)
        logging.debug(f"[*] ARP request for {ip} leads to {mac}")
        if mac and len(mac[0]):
            with LOCK:
                RESULT[ip]['state'] = 'alive'
                RESULT[ip]['method'] = 'arp' 
                RESULT[ip]['mac'] = mac[0][0].answer.hwsrc
                outfile.write(ip+'\n')
                print(f"Salut {ip} ({mac[0][0][1].hwsrc}), ça fart ?")
    except Exception as e:
        logging.debug(f"[!] ARP request for {ip} failed due to {e}")

def NetBIOS_Lookup(ip, outfile, timeout):
    """To do : add netbios over tcp (139) et netbios over SMB (445)"""
    global RESULT
    global LOCK
    try:
        nb = NetBIOS()
        nb_name = nb.getnetbiosname(ip)
        logging.debug(f"[*] NetBIOS resolution for {ip} leads to {nb_name}")
        if nb_name:
            with LOCK:
                RESULT[ip]['state'] = 'alive'
                RESULT[ip]['method'] = 'netbios'
                RESULT[ip]['netbios'] = nb_name
                outfile.write(ip + '\n')
                print(f"Salut {ip} ({nb_name}), ça fart ?")
    except Exception as e:
        logging.debug(f"[!] NetBIOS resolution for {ip} failed due to {e}")

def ICMP_Lookup(ip, outfile, timeout):
    global RESULT
    global LOCK
    try:
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        if not response or response[ICMP].type != 0:
            packet = IP(dst=ip) / ICMP(type=13) / b'\x00\x00\x00\x00\x00\x00\x00\x00'
            response = sr1(packet, timeout=timeout, verbose=0)
        logging.debug(f"[*] ICMP request for {ip} leads to {response}")
        if response and response[ICMP].type !=3:
            with LOCK:
                RESULT[ip]['state'] = 'alive'
                RESULT[ip]['method'] = 'icmp'
                outfile.write(ip + '\n')
                print(f"Salut {ip} ({response[ICMP]}), ça fart ?")
    except Exception as e:
        logging.debug(f"[!] ICMP resquest for {ip} failed due to {e}")

def TCP_Lookup(ip, outfile, timeout):
    global RESULT
    global LOCK
    global TCP_PING_PORTS
    for p in TCP_PING_PORTS:
        try:
            packet = IP(dst=ip) / TCP(dport=p, flags='S')
            response = sr1(packet, timeout=timeout, verbose=0)
            if not response:
                packet = IP(dst=ip) / TCP(dport=p, flags='A')
                response = sr1(packet, timeout=timeout, verbose=0)
            logging.debug(f"[*] TCP Scan for {ip}:{p} leads to {response}")
            if response:
                with LOCK:
                    RESULT[ip]['state'] = 'alive'
                    RESULT[ip]['method'] = 'tcp'
                    outfile.write(ip + '\n')
                    print(f"Salut {ip}:{p}, ça fart ?")
                    return
        except Exception as e:
            logging.debug(f"[!] TCP Scan for {ip}:{p} failed due to {e}")

def UDP_Lookup(ip, outfile, timeout):
    global RESULT
    global LOCK
    global UDP_PING_PORTS
    for p in UDP_PING_PORTS:
        try:
            packet = IP(dst=ip) / UDP(dport=p)
            response = sr1(packet, timeout=timeout, verbose=0)
            logging.debug(f"[*] UDP Scan for {ip}:{p} leads to {response}")
            if response:
                with LOCK:
                    RESULT[ip]['state'] = 'alive'
                    RESULT[ip]['method'] = 'udp'
                    outfile.write(ip + '\n')
                    print(f"Salut {ip}:{p}, ça fart ?")
                    return
        except Exception as e:
            logging.debug(f"[!] UDP Scan for {ip}:{p} failed due to {e}")

#################
# ORCHESTRATION #
#################

def launcher(method, outfile, timeout):
    global RESULT
    launchers = {
            'dns': DNS_Lookup,
            'arp': ARP_Lookup,
            'netbios': NetBIOS_Lookup,
            'icmp': ICMP_Lookup,
            'tcp': TCP_Lookup,
            'udp': UDP_Lookup
            }
    threads = []
    for ip in (ip for ip in RESULT if RESULT[ip]['state']=='silent'):
        t = Thread(target=launchers[method], args=(ip, outfile, timeout))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def salut(method, f, timeout):
    global RESULT
    """perform host discovery"""
    f.write('# Hosts alive\n')
    for m in method:
        f.write(f"## {m.upper()} ping\n")
        launcher(m, f, timeout)
    
def main():
    global RESULT
    parser = argparse.ArgumentParser(description='Find which hosts are alive in a given subnet.\
            \nUse various techniques implemented by nmap : ARP, ICMP, SYN, ...\
            \nDesigned to allow interrupt and resume\
            \nCompatible with the SubZero Project', add_help=True)
    parser.add_argument('-w', action="store", dest="outfile", default='tuvienssurfer.txt',
            help='Filename of the output')
    parser.add_argument('-t', '--timeout', action='store', default=5,
            help='Timeout in seconds')
    parser.add_argument('-r', '--resume', action='store', 
            help='Provide a result file to allow continuation')
    parser.add_argument('SUBNET', action="store",
            help='A subnet in the form 185.230.26.80/30 (could be 10.0.1.2/32)')
    parser.add_argument('-v', '--verbosity', action="store_true", default=False,
            help="Display every request result")
    parser.add_argument('-j', '--json', action="store_true",
            help="Export as JSON format", default=False)
    parser.add_argument('-q', '--quiet', action="store_true", default=False,
            help="Only display raw alive hosts (useful to feed other tools)")
    parser.add_argument('-m', '--method', action='store', default='dns,arp,netbios,icmp,tcp,udp',
            help="Specify the methods you want to use for discovery, comma separated")
    args = parser.parse_args()

    if args.verbosity:
        logging.basicConfig(level=logging.DEBUG)
    try:
        target = ipaddress.ip_network(args.SUBNET)
        tm = int(args.timeout)
        method = args.method.split(',')
        for m in method:
            if m not in ('dns', 'arp', 'netbios', 'icmp', 'tcp', 'udp'):
                print(f"[!] Unrecognized method: {m}")
                exit(1)
    except Exception as e:
        print(f"[!] Bad input : {e}")
        exit(1)
    with open(args.outfile, "w") as f:
        f.write(f"# Target : {target}\n")
        for ip in target:
            if not to_avoid(str(ip)):
                RESULT[str(ip)] = {"state": "silent"}
            else:
                logging.debug(f"[!] {ip} will be ignored as probably not a host")
        logging.debug(f"[*] targets are :\n{RESULT.keys()}")
        salut(method, f, tm)
        logging.debug(f"[*] Hosts information are:\n{RESULT}")

if __name__ == '__main__':
    main()
