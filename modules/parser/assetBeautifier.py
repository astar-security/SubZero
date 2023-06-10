import json
from columnar import columnar
import sys

def beautifyJson(filename):
    f = open(filename, "r")
    try:
        asset = json.loads(f.read())
    except Exception as e:
        print('[!] Error during json parsing')
        print(filename,e)
        exit(1)

    headers = ['name', 'ip', 'os', 'mac', 'manufacturer']
    name = asset['fqdn']
    if name == "" and "name0" in asset["additional names"]:
        name = asset["additional names"]["name0"]
    data = [[name,
            asset['ipv4']['address'],
            asset['os']['cpe'],
            asset['mac']['address'],
            asset['mac']['manuf']]]

    table = columnar(data, headers)
    print(table)
    
    headers = ['port', 'service']
    data = []
    for app in asset['applicative']:
        service = asset['applicative'][app]['name']
        if service == "":
            service = asset['applicative'][app]['protocol'] 
        data.append([asset['applicative'][app]['port']['type'] + ' ' + asset['applicative'][app]['port']['number'],service])
    table = columnar(data, headers)
    print(table)
    print('\n')

if len(sys.argv) < 2:
    print("Usage : give only one json asset file")
    exit(0)

beautifyJson(sys.argv[1])
