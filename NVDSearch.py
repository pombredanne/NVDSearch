# Written by Nate Holmdahl for Itron 2019
import json
import smtplib
import os
import requests
import io
import zipfile
import sys
from colorama import init, Fore, Back, Style 
init(convert=True)

FILE = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip"
SMTP = "spo-smtp.itron.com"

# This is the mailing list and it must be formatted a specific way.
# Here is an example of how to format one entry in the mailing list:
# 
# :start
# Nate.Holmdahl@itron.com
# linux_kernel 3.0 HIGH
# debian_linux - HIGH
# :end
# 
# Note the scructure of the search term; PRODUCT VERSION SEVERITY.
# Use '-' in place of the version to search all versions.
# You can have as many search terms (i.e. "linux_kernel 3.0 HIGH") per
# entry as you want, but you must to have an entry for each
# person that needs to be on the mailing list.

# This program specifically searches for the product_name value.
        
mail_list = """
        :start
        email1@itron.com
        linux_kernel 3.0 HIGH
        debian_linux - LOW
        :end
        :start
        email2@itron.com
        linux_kernel 3.0 HIGH
        debian_linux - LOW
        :end
"""


# Downloads a zip from a url and returns a generator over that unzipped file
# Use var = next(generator_name) to access file. Url parameter is a string.
def download_extract_zip(url):
    response = requests.get(url)
    with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:
        for zipinfo in thezip.infolist():
            with thezip.open(zipinfo) as thefile:
                yield thefile

# Returns the low and high version number in a vulnerbility range.
def get_ver_range(vul):
    return vul[0].get("version_value"), vul[len(vul) - 1].get("version_value")

# Tests if a given version (string) is inbetween or out of the low 
# and high values of a version range. All parameters are strings.
# Returns boolean
def in_ver_range(ver, low, high):
    if ver == '-': # '-' means "All Versions"
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

# Searches a database for a vulnerability.
# All parameters are strings.
def search(product, version, severity):
    # Check severity
    print()
    product = product.lower()
    severity = severity.upper()
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
    
    # Download and unzip the .json CPE file
    f = download_extract_zip(FILE)
    fi = next(f)
    x = json.load(fi)

    data = x["CVE_Items"]
    vuls = []
    result = ""
    for vul in data:
        valid = True
        if len(vul["cve"]["affects"]["vendor"]["vendor_data"]) > 0 and len(vul["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"]) > 0 and (vul["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0].get("product_name") == product):  # If the vulnerability has vendor data and matches our search
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
                    result += "Severity: " + level + "\n"
                    print("Severity: " + Fore.YELLOW + level)
                elif level == "MEDIUM":
                    result += "Severity: " + level + "\n"
                    print("Severity: " + Fore.YELLOW + level)
                elif level == "HIGH":
                    result += "Severity: " + level + "\n"
                    print("Severity: " + Fore.RED + level)
                elif level == "CRITICAL":
                    result += "Severity: " + level + "\n"
                    print("Severity: " + Fore.RED + level)
                print(Fore.WHITE + "Description: " + vul["cve"]["description"]["description_data"][0].get("value"))
                print("Link: http://nvd.nist.gov/vuln/detail/" + vul["cve"]["CVE_data_meta"].get("ID"))
                print()
                result += "Description: " + vul["cve"]["description"]["description_data"][0].get("value") + "\n"
                result += "Link: http://nvd.nist.gov/vuln/detail/" + vul["cve"]["CVE_data_meta"].get("ID") + "\n\n"
    return result

# Opens a wizard to manually search for vulnerabilities.
def manual():
    
    destination = input("Please type the destination email: ")

    print(Fore.GREEN + 'NVD Searcher v0.1')
    print("-----------------")
    responses = []
    while True:
        if len(responses) != 0:
            print("Search terms:")
            for resp in responses:
                print("   " + resp)
            print()
        print(Fore.WHITE + "Please enter your search terms in the following format:")
        print("PRODUCT VERSION SEVERITY")
        print("Or type 'help' for help")
        print("or 'done' to begin the search.")
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
        elif response == "done":
            break
        else:
            responses.append(response)
    finalbody = ""
    for resp in responses:
        params = resp.split()
        if len(params) == 3:
            print("")
            print("---------------")
            print("Searching for vulnerabilities related to")
            print(params[0].lower() + " version " + params[1] + ", severity " + params[2].upper())
            print("---------------")
            finalbody += "---------------\n"
            finalbody += "Searching for vulnerabilities related to\n"
            finalbody += params[0].lower() + " version " + params[1] + ", severity " + params[2].upper() + "\n"
            finalbody += "---------------\n"
            finalbody += search(params[0].lower(), params[1], params[2].upper()) + "\n"
            print("------SEARCH COMPLETE------")
    # Build Email
    message = "Subject: NVD Search Results\n\nThe NVD Search results have come in for the following search terms:\n\n"
    for resp in responses:
        message += "   " + resp + "\n"
    message += "\nNote: '-' denotes 'all versions'\n\n" + finalbody
    # Establish secure connection
    server = smtplib.SMTP(SMTP, "25") # (smtp server, port number)
    server.sendmail("NVDItronReport", destination, message)

# Reads a mailing list (located at the top of this script) and automatically
# searches the most recent NVD database. Will build and send a formatted email
# to all members of the mailing list. This is the main usage of this script.
def automatic():
    lines = mail_list.splitlines()
    for i in range(len(lines)):
        if lines[i].strip() == ":start":
            searches = []
            email = lines[i+1].strip()
            j = i + 2
            while lines[j].strip() != ":end":
                searches.append(lines[j].strip())
                j += 1
            finalbody = ""
            for s in searches:
                params = s.split()
                if len(params) == 3:
                    finalbody += "---------------\n"
                    finalbody += "Searching for vulnerabilities related to\n"
                    finalbody += params[0].lower() + " version " + params[1] + ", severity " + params[2].upper() + "\n"
                    finalbody += "---------------\n"
                    finalbody += search(params[0].lower(), params[1], params[2].upper()) + "\n"
            # Build Email
            message = "Subject: NVD Search Results\n\nThe NVD Search results have come in for the following search terms:\n\n"
            for resp in searches:
                message += "   " + resp + "\n"
            message += "\nNote: '-' denotes 'all versions'\n\n" + finalbody
            # Establish secure connection
            server = smtplib.SMTP(SMTP, "25") # (smtp server, port number)
            server.sendmail("NVDItronReport", email, message)

if len(sys.argv) == 1:
    print("Please use the flags \"--auto\" or \"manual\" to run this script.")
elif sys.argv[1] == "--auto" or sys.argv[1] == "-a":
    automatic()
elif sys.argv[1] == "--manual" or sys.argv[1] == "-m":
    manual()
else:
    print("Please use the flags \"--auto\" or \"manual\" to run this script.")