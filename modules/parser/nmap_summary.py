#!/usr/bin/python3

import json
import ipaddress
import xml.etree.ElementTree as ET
import uuid
import requests
import argparse
import os.path
import xlsxwriter

# de nada
IPSTACK_API_KEY="6f77d543cd2422ae17ac5ca858202ca9"

META = {'ports': {}, 'os':{}, 'apps':{}}

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

def nmap2json(host, geo, META):
    # get onyl live hosts
    if host.find("status").attrib["state"] == "down":
        return {"id": None}

    # create an initial id
    asset = {"id":str(uuid.uuid1())}

    # set ipv4 and mac addresses
    asset['ipv4'] = {'address': '', 'public': '', 'location': ''}
    asset['mac'] = {'address': '', 'manuf': ''} 
    for a in host.findall("address"):
        asset[a.get("addrtype")]['address'] = a.get("addr")
        if a.get('addrtype') == 'mac':
            asset['mac']['manuf'] = a.get('vendor')
        else:
            asset['ipv4']['public'] = ipaddress.ip_address(asset['ipv4']['address']).is_global
            if asset['ipv4']['public'] and geo:
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
    asset['filtering'] = {"default": "", "exception": []}
    for a in host.find('ports').iter('extraports'):
        asset['filtering']["default"] = a.get('state')
    for a in host.find('ports').iter('port'):
        if a.find('state').get('state') != 'open':
            asset['filtering']['exception'].append({"number": a.get('portid'), "type": a.get('protocol'), "state": a.find('state').get('state')})
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
            if f"{a.get('protocol')}/{a.get('portid')}" not in META['ports']:
                META['ports'][f"{a.get('protocol')}/{a.get('portid')}"] = []
            META['ports'][f"{a.get('protocol')}/{a.get('portid')}"].append(asset['ipv4']['address'])
            s = a.find('service')
            if s:
                netbios = s.get('hostname')
                if netbios:
                    fqdn.add(netbios)
                p = s.get('product')
                v = s.get('version')
                asset['applicative'][thisapp]['name'] += (p if p else '')
                asset['applicative'][thisapp]['name'] += (' ' + v if v else '')
                asset['applicative'][thisapp]['protocol'] = s.get('name')
                asset['applicative'][thisapp]['cleartext'] = str(checkCleartext(s))
                if asset['applicative'][thisapp]['name'] not in META['apps']:
                    META['apps'][asset['applicative'][thisapp]['name']] = []
                META['apps'][asset['applicative'][thisapp]['name']].append(asset['ipv4']['address'])
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

    return asset

def export_json(assets):
    # export results as json
    for asset in assets:
        if asset["id"]:
            f = open(asset["id"]+".json","w")
            f.write(json.dumps(asset))
            f.close()

def export_xlsx(assets, META):
    workbook = xlsxwriter.Workbook('nmap_summarized.xlsx')
    firstline_format = workbook.add_format({'font_color': '#F4F5F5', 
                                        'align': 'vcenter', 
                                        'align': 'center',
                                        'text_wrap': True,
                                        'bg_color': '#051F34'})
    normalline_format = workbook.add_format({'text_wrap': True, 'align': 'vcenter'})
    attentionline_format = workbook.add_format({'text_wrap': True, 'align': 'vcenter', 'bg_color': '#ff6400'})
    ta = workbook.add_worksheet('Assets')
    ta.set_column(0, 0, 15)
    ta.set_column(1, 1, 23)
    ta.set_column(5, 6, 45)
    start = 0
    for asset in assets:
        if asset["id"]:
            ta.write(start, 0, f"{asset['ipv4']['address']}\n{asset['fqdn']}\n{asset['mac']['address']}\n{asset['mac']['manuf']}")
            ta.write(start, 1, cpe if (cpe := asset['os']['cpe']) != "" else asset['os']['desc'])
            for app, desc in asset['applicative'].items():
                ta.write(start, 2, f"{desc['port']['type'].upper()} {desc['port']['number']}")
                ta.write(start, 3, "Open")
                ta.write(start, 4, desc['protocol'])
                ta.write(start, 5, desc['name'])
                ta.write(start, 6, desc['cpe'])
                start += 1
            for ex in asset['filtering']['exception']:
                ta.write(start, 2, f"{ex['type'].upper()} {ex['number']}")
                ta.write(start, 3, ex['state'].capitalize())
                start += 1
            ta.write(start, 2, "default")
            ta.write(start, 3, asset['filtering']['default'].capitalize())
            start += 2

    for i in range(start):
        ta.set_row(i, None, normalline_format)

    po = workbook.add_worksheet('Ports')
    start = 0
    for p in META['ports']:
        po.write(start, 0, p)
        for asset in META['ports'][p]:
            po.write(start, 1, asset)
            start += 1
        start += 2
    
    ap = workbook.add_worksheet('Apps')
    start = 0
    for a in META['apps']:
        ap.write(start, 0, a)
        for asset in META['apps'][a]:
            ap.write(start, 1, asset)
            start += 1
        start += 2

    workbook.close()



def friendly_print(assets):
    for asset in assets:
        if asset["id"]:
            print('\n---', asset['ipv4']['address'])
            print(f"default: {asset['filtering']['default']}")
            for app, desc in asset['applicative'].items():
                print(f"{desc['port']['type'].upper()} {desc['port']['number']} Open")
            for ex in asset['filtering']['exception']:
                print(f"{ex['type'].capitalize()} {ex['number']} {ex['state']}")



def main():
    parser = argparse.ArgumentParser(description='Convert Nmap XML format to report table\
            compatible with the SubZero Project', add_help=True)
    parser.add_argument('-w', action="store", dest="path", default='.', 
            help='A path to store the files. Default is current folder')
    parser.add_argument('NMAP_XML_FILE', action="store",  
            help='A nmap result file in xml format')
    parser.add_argument('-g', '--geolocation', action="store_true",
            help="Ask ipstack for the GPS location of the IP", default=False)
    parser.add_argument('-j', '--json', action="store_true",
            help="Write one json file per target", default=False)
    parser.add_argument('-x', '--xlsx', action="store_true",
            help="Write a XLSX summurized file", default=False)
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        print('[!] Given path does not exist')
        return 1
    nmap = ET.parse(args.NMAP_XML_FILE)
    r = nmap.getroot()
    global_ports = {'tcp': set(), 'udp': set()}
    assets = [nmap2json(host, args.geolocation, META) for host in r.iter("host")]
    if args.xlsx:
        export_xlsx(assets, META)
    if args.json:
        export_json(assets)

    friendly_print(assets)

    print(f"\nT:{','.join([p.split('/')[1] for p in META['ports'] if 'tcp' in p])},U:{','.join([p.split('/')[1] for p in META['ports'] if 'udp' in p])}")

if __name__ == '__main__':
    main()
