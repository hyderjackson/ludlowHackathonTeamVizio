import csv

import requests

import ipaddress


def writeWhoIsFromCSV(path, outputPath):
    with open(path, newline="", encoding="utf-8") as f:
        addresses = []
        reader = csv.reader(f)
        header = next(reader)       # first row
        for row in reader:
            source = row[1]
            dest = row[2]
            if(source not in addresses):
                if(is_valid_public_ip(source)):
                    #NOTE: this doesn't correct invalid addresses...
                    addresses.append(source)

            if(dest not in addresses):
                if(is_valid_public_ip(dest)):
                    addresses.append(dest)

        print(addresses)


        addressToName = {}
        for address in addresses:
            data = requests.get("https://rdap.arin.net/registry/ip/" + str(address), timeout=10).json()
            relevantData = {}
            relevantData["endAddress"] = data["endAddress"]
            res = parse_rdap(data)
            addressToName[address] = res


            with open(outputPath + ".txt", "w", encoding="utf-8") as f:
                for address in addressToName.keys():
                    f.write(str(address) + " Information: \n")
                    f.write(str(addressToName[address]) + "\n----------------------------------\n")

def vcard_get(entity, prop):
    for p in entity["vcardArray"][1]:
        if p[0] == prop:
            return p
    return None

def parse_rdap(data):
    registrant = next(
        (e for e in data.get("entities", []) if "registrant" in e.get("roles", [])),
        None,
    )

    result = {
        "network_name": data.get("name"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "owner": None,
        "description": None,
        "location": None,
    }

    if registrant:
        fn = vcard_get(registrant, "fn")
        adr = vcard_get(registrant, "adr")
        result["owner"] = fn[3] if fn else None
        result["location"] = adr[1].get("label") if adr else None

        remarks = registrant.get("remarks", [])
        if remarks:
            result["description"] = " ".join(remarks[0].get("description", [])).strip()

    return result

class WhoIsResult:
    def __init__(self, startAddress, endAddress, name):
        self.startAddress = startAddress
        self.endAddress = endAddress
        self.name = name

    def __str__(self):
        return f"name: {self.name} \n start: {self.startAddress}\nend: {self.endAddress}\n"
def is_valid_public_ip(address: str) -> bool:
    """Return True if `address` is a well-formed, publicly routable IP address."""
    if not isinstance(address, str):
        return False

    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return False

    return ip.is_global
    


writeWhoIsFromCSV("ex.csv")