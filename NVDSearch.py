import json
from colorama import init, Fore, Back, Style 
init(convert=True)

# Reutrns the count of all low, medium, high, and critical severity CPEs
def count_severity():
    with open("nvdcve-1.0-modified.json", "r") as f:
        data = json.load(f)

    x = data["CVE_Items"]
    low = 0
    med = 0
    high = 0
    critical = 0

    for vul in x:
        if "baseMetricV2" in vul["impact"].keys():
            if vul["impact"]["baseMetricV2"].get("severity") == "LOW":
                low += 1
            elif vul["impact"]["baseMetricV2"].get("severity") == "MEDIUM":
                med += 1
            elif vul["impact"]["baseMetricV2"].get("severity") == "HIGH":
                high += 1
        if "baseMetricV3" in vul["impact"].keys():
            if vul["impact"]["baseMetricV3"].get("severity") == "LOW":
                low += 1
            elif vul["impact"]["baseMetricV3"].get("severity") == "MEDIUM":
                med += 1
            elif vul["impact"]["baseMetricV3"].get("severity") == "HIGH":
                high += 1

    print("LOW: " + str(low))
    print("MEDIUM: " + str(med))
    print("HIGH: " + str(high))

    return low, med, high

def get_vendors():
    with open("nvdcve-1.0-modified.json", "r") as f:
        data = json.load(f)

    x = data["CVE_Items"]
    for vul in x:
        if len(vul["cve"]["affects"]["vendor"]["vendor_data"]) > 0:
            print(vul["cve"]["affects"]["vendor"]["vendor_data"][0].get("vendor_name"))

def get_ver_range(vul):
    return vul[0].get("version_value"), vul[len(vul) - 1].get("version_value")

def in_ver_range(ver, low, high):
    if ver == '-':
        return True
    ver_lst = []
    for c in ver:
        if c != '.':
            ver_lst.append(c)
    if low == '-':
        return True
    low_lst = []
    for c in low:
        if c != '.':
            low_lst.append(c)
    high_lst = []
    for c in high:
        if c != '.':
            high_lst.append(c)
    for i in range(len(ver_lst)):
        if len(low_lst) > i:
            if int(ver_lst[i]) < int(low_lst[i]):
                return False
    for i in range(len(high_lst)):
        if len(ver_lst) > i:
            if int(ver_lst[i]) > int(high_lst[i]):
                return False
    if len(ver) > len(high):
        return False

    return True

# Searches a database for a vulnerability
def search(product, version, severity):
    print()
    product = product.lower()
    sev = 0
    if severity == "LOW":
        sev = 0.1
    elif severity == "MEDIUM":
        sev = 4.0
    elif severity == "HIGH":
        sev = 7.0
    elif severity == "CRITICAL":
        sev = 9.0
    else:
        print("Please specify the severity as either LOW, MEDIUM, HIGH, or CRITICAL")
        return
    with open("nvdcve-1.0-modified.json", "r") as f:
        x = json.load(f)

    data = x["CVE_Items"]
    vuls = []
    for vul in data:
        valid = True
        if len(vul["cve"]["affects"]["vendor"]["vendor_data"]) > 0 and (vul["cve"]["affects"]["vendor"]["vendor_data"][0].get("vendor_name") == product):  # If the vulnerability has vendor data and matches our search
            low, high = get_ver_range(vul["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"])
            if low == "-":  # All versions
                valid = True
            elif not in_ver_range(version, low, high): # Version
                valid = False
            cvss_ver = 3
            if "baseMetricV3" in vul["impact"].keys():
                if vul["impact"]["baseMetricV3"]["cvssV3"].get("baseScore") < sev:
                    valid = False
            elif "baseMetricV2" in vul["impact"].keys():
                cvss_ver = 2
                if severity == "LOW":
                    sev = 0.0
                elif severity == "MEDIUM":
                    sev = 4.0
                elif severity == "HIGH":
                    sev = 7.0
                if vul["impact"]["baseMetricV2"]["cvssV2"].get("baseScore") < sev:
                    valid = False
            if valid:
                if cvss_ver == 3:
                    score = vul["impact"]["baseMetricV3"]["cvssV3"].get("baseScore")
                    level = ""
                    if score < 4:
                        level = "LOW"
                    elif score < 7:
                        level = "MEDIUM"
                    elif score < 9:
                        level = "HIGH"
                    else:
                        level = "CRITICAL"
                elif cvss_ver == 2:
                    score = vul["impact"]["baseMetricV2"]["cvssV2"].get("baseScore")
                    level = ""
                    if score < 4:
                        level = "LOW"
                    elif score < 7:
                        level = "MEDIUM"
                    else:
                        level = "HIGH"
                if level == "LOW":
                    print("Severity: " + Fore.YELLOW + level)
                elif level == "MEDIUM":
                    print("Severity: " + Fore.YELLOW + level)
                elif level == "HIGH":
                    print("Severity: " + Fore.RED + level)
                elif level == "CRITICAL":
                    print("Severity: " + Fore.RED + level)
                print(Fore.WHITE + "Description: " + vul["cve"]["description"]["description_data"][0].get("value"))
                print("Link: http://nvd.nist.gov/vuln/detail/" + vul["cve"]["CVE_data_meta"].get("ID"))
                print()


print(Fore.GREEN + 'NVD Searcher v0.1')
print("-----------------")
while True:
    print(Fore.WHITE + "Please enter your search in the following format:")
    print("PRODUCT VERSION SEVERITY")
    print("Or type 'help' or 'quit'")
    print()
    response = input("Response: ")
    if response == "help":
        print()
        print(Fore.WHITE + "This tool will search an NVD database for all vulnerabilities")
        print("pertaining to the provided product name, product version, and")
        print("desired vulnerability severity. Use '-' in place of the version")
        print("to search all product versions. The tool will find all vulnerabilities")
        print("that are at least as severe as the given severity level (i.e. HIGH will")
        print("show HIGH and CRITICAL vulnerabilities, but skip over LOW and MEDIUM).")
        print()
    elif response == "quit":
        break
    else:
        params = response.split()
        if len(params) == 3:
            print("")
            print("---------------")
            print("Searching for vulnerabilities related to")
            print(params[0].lower() + " version " + params[1] + ", severity " + params[2].upper())
            print("---------------")
            search(params[0].lower(), params[1], params[2].upper())
            print("------SEARCH COMPLETE------")

