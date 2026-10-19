import csv
import requests
import ipaddress

# NOTE: The command used to export the pcapng to a csv file is:
# tshark -r capture.pcapng -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e _ws.col.Info -E header=y -E separator=, > capture.csv
# Please use this command, or something similar, so that the write code works, as it checks that the source and destination are the first and second index, respectively
def writeWhoIsFromCSV(path, outputPath):
    with open(path, newline="", encoding="utf-8") as f:
        #List of unique addrresses
        addresses = []

        #Read from the file
        reader = csv.reader(f)

        for row in reader:
            #For each row, take the source and destination address
            source = row[1]
            dest = row[2]

            #If the source is not in our list of addresses and it is a valid, non-private IPv4 address, add it to the list
            if(source not in addresses):
                if(is_valid_public_ip(source)):
                    #NOTE: this doesn't correct invalid addresses...
                    addresses.append(source)

            #If the destination is not in our list of addresses and it is a valid, non-private IPv4 address, add it to the list
            if(dest not in addresses):
                if(is_valid_public_ip(dest)):
                    addresses.append(dest)


        #Create a dictionary to store API call results
        addressToName = {}
        for address in addresses:
            #Use the rdap API to perform a whois lookup
            data = requests.get("https://rdap.arin.net/registry/ip/" + str(address), timeout=10).json()
            #Call helper method to parse relevant data
            res = parse_rdap(data)
            #Store the data in the dictionary
            addressToName[address] = res


            #Store the output in a txt file
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

def is_valid_public_ip(address: str) -> bool:
    """Return True if `address` is a well-formed, publicly routable IP address."""
    if not isinstance(address, str):
        return False

    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return False

    return ip.is_global
    


# writeWhoIsFromCSV("source", "dest")