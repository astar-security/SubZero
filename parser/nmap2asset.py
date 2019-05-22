import json
import xml.etree.ElementTree as ET
import uuid

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
            asset['ipv4']['location'] = ""

    # set fqdn

    # set os cpe
    asset['os'] = {"cpe":[''], "desc":"", "os users":{}}

    # set fqdn
    asset['fqdn'] = ""
    asset['additional names'] = {}
    fqdn = set()

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
            # get all possible hostname
            fqdn.add(s.get('hostname'))
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
        if i and asset['fqdn'] == "" and len(i.split('.'))==3:
            asset['fqdn'] = i
        elif i:
            asset['additional names']['name'+str(counter)] = i
            counter += 1

    # export results as json
    f = open(asset["id"]+".json","w")
    f.write(json.dumps(asset))
    f.close()


tree = ET.parse("nmap-top100.xml")
r = tree.getroot()
for c in r.iter("host"):
    nmap2json(c)
