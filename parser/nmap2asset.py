#!/usr/bin/python3

import json
import ipaddress
import xml.etree.ElementTree as ET
import uuid
import requests
import argparse
import os.path

# de nada
IPSTACK_API_KEY="6f77d543cd2422ae17ac5ca858202ca9"

def getLocation(ipv4):
    r = requests.get(f"http://api.ipstack.com/{ipv4}?access_key={IPSTACK_API_KEY}")
    loc = r.json()
    location = {}
    try:
        location["country"] = loc["country_name"]
        location["city"] = loc["city"]
    except:
        pass
    return location

def checkCleartext(node):
    secured = ['ssh']
    return not(node.get('tunnel') == 'ssl' or node.get('name') in secured)

def nmap2json(host):
    # get onyl live hosts
    if host.find("status").attrib["state"] == "down":
        return

    # create an initial id
    asset = {"id":str(uuid.uuid1())}

    # set ipv4 and mac addresses
    for a in host.findall("address"):
        asset[ a.get("addrtype") ] = {"address":a.get("addr")}
        if a.get('addrtype') == 'mac':
            asset['mac']['manuf'] = a.get('vendor')
        else:
            asset['ipv4']['public'] = ipaddress.ip_address(asset['ipv4']['address']).is_global
            if asset['ipv4']['public']:
                asset['ipv4']['location'] = getLocation(asset["ipv4"]["address"])
            
    # set fqdn

    # set os cpe
    asset['os'] = {"cpe":[''], "desc":"", "os users":{}}

    # set fqdn
    asset['fqdn'] = ""
    asset['additional names'] = {}
    fqdn = set()
    for hostname in host.find("hostnames").iter("hostname"):
        fqdn.add(hostname.get("name"))

    # set applicative
    asset['applicative'] = {}
    counter = 0
    for a in host.find('ports').iter('port'):
        if a.find('state').get('state') == 'open':
            thisapp = 'app' + str(counter)
            asset['applicative'][thisapp] = {"cpe":"", 
                "name":"",
                "users":{},
                "port":{"type":"", "number":"", "ttl":"", "winsize":"", "id":""},
                "protocol":"",
                "cleartext":"True"}
            counter += 1
            asset['applicative'][thisapp]['port']['type'] = a.get('protocol')
            asset['applicative'][thisapp]['port']['number'] = a.get('portid')
            s = a.find('service')
            netbios = s.get('hostname')
            if netbios:
                fqdn.add(netbios)
            p = s.get('product')
            v = s.get('version')
            asset['applicative'][thisapp]['name'] += (p if p else '')
            asset['applicative'][thisapp]['name'] += (' ' + v if v else '')
            asset['applicative'][thisapp]['protocol'] = s.get('name')
            asset['applicative'][thisapp]['cleartext'] = str(checkCleartext(s))
            for c in s.findall('cpe'):
                if "cpe:/a" in c.text:
                    asset['applicative'][thisapp]['cpe'] += c.text
                if "cpe:/o" in c.text:
                    asset['os']['cpe'].append(c.text)
    
    # get only the longest os cpe
    asset['os']['cpe'] = max(asset['os']['cpe'], key=len)
   
    # reduce the possible fqdn
    counter = 0
    for i in fqdn:
        if asset['fqdn'] == "" and len(i.split('.'))==3:
            asset['fqdn'] = i
        else:
            asset['additional names']['name'+str(counter)] = i
            counter += 1

    # export results as json
    f = open(asset["id"]+".json","w")
    f.write(json.dumps(asset))
    f.close()


def main():
    parser = argparse.ArgumentParser(description='Convert Nmap XML format to json\
            compatible with the SubZero Project', add_help=True)
    parser.add_argument('-w', action="store", dest="path", default='.', 
            help='A path to store the files. Default is current folder')
    parser.add_argument('NMAP_XML_FILE', action="store",  
            help='A nmap result file in xml format')
    parser.add_argument('-g', '--geolocation', action="store_true",
            help="Ask ipstack for the GPS location of the IP", default=False)
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        print('[!] Given path does not exist')
        return 1
    nmap = ET.parse(args.NMAP_XML_FILE)
    r = nmap.getroot()
    for host in r.iter("host"):
        nmap2json(host)

if __name__ == '__main__':
    main()
