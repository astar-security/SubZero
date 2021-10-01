import json
from columnar import columnar

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


l = ["0cdebfce-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfcf-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd0-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd1-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd2-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd3-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd4-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd5-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd6-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd7-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd8-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfd9-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfda-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfdb-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfdc-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfdd-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfde-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfdf-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe0-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe1-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe2-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe3-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe4-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe5-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe6-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe7-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe8-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfe9-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfea-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfeb-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfec-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfed-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfee-7c1f-11e9-9662-2016b91ec396.json",
"0cdebfef-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff0-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff1-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff2-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff3-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff4-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff5-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff6-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff7-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff8-7c1f-11e9-9662-2016b91ec396.json",
"0cdebff9-7c1f-11e9-9662-2016b91ec396.json",
"0cdebffa-7c1f-11e9-9662-2016b91ec396.json"]

for i in l:
    beautifyJson(i)
