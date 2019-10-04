#!/usr/bin/env python
# pip install asn1
from sys import argv, stdout
from os import system, remove
from urlparse import urlparse
import re
import dfu
import ssl
import asn1
import math
import json
import dfuexec
import httplib
import usbexec
import zipfile
import plistlib

if len(argv) < 4:
    print("Usage: " + argv[0] + " <device ID> <version> <output.json> [skip download]")
    exit(1)

dev = dfu.acquire_device()
serial_number = dev.serial_number
print("Found:" + serial_number)
if not "PWND:[" in serial_number:
    print "Please enable pwned DFU Mode first."
    exit(4)
cpid_m = re.search("CPID:([0-9A-F]{4})", serial_number)
if cpid_m == None:
    print("Could not find CPID in serial")
    exit(4)
cpid = cpid_m.group(1)
bdid_m = re.search("BDID:([0-9A-F][0-9A-F])", serial_number)
if bdid_m == None:
    print("Could not find BDID in serial")
    exit(4)
bdid = bdid_m.group(1)
dfu.release_device(dev)

if len(argv) < 5: 
    def getFile(url):
        uri = urlparse(url)
        con = httplib.HTTPSConnection(uri.netloc, context=ssl.SSLContext(ssl.PROTOCOL_SSLv23))
        con.request("GET", uri.path)
        res = con.getresponse()
        if math.floor(res.status / 100) != 2:
            print(res.status)
            return None
        retval = res.read()
        con.close()
        return retval

    firmwares_json = getFile("https://api.ipsw.me/v4/device/" + argv[1])
    if firmwares_json == None:
        print("Unknown device type " + argv[1])
        exit(2)
    firmwares = json.loads(firmwares_json)
    if firmwares == None:
        print("Error decoding firmwares JSON")
        exit(2)

    try:
        firm = next(item for item in firmwares["firmwares"] if item["version"] == argv[2])
    except StopIteration:
        print("Unknown version " + argv[2] + " for device " + argv[1])
        exit(3)
    if firm == None:
        print("Unknown version " + argv[2] + " for device " + argv[1])
        exit(3)

    print("Downloading iOS " + firm["version"] + " (" + firm["buildid"] + ") for device " + firm["identifier"] + "...")
    system("curl -o firmware.ipsw -L --progress-bar " + firm["url"])

print("Reading manifest...")
zip = zipfile.ZipFile("firmware.ipsw")
manifest = plistlib.readPlistFromString(zip.read("BuildManifest.plist"))

print("Reading keys...")
output = {}

try:
    identity = next(item for item in manifest["BuildIdentities"] if item["ApChipID"] == "0x" + cpid and item["ApBoardID"] == "0x" + bdid)
except StopIteration:
    print("Could not find identity for CPID " + cpid + " and BDID " + bdid + " in manifest")
    exit(5)
if identity == None:
    print("Could not find identity for CPID " + cpid + " and BDID " + bdid + " in manifest")
    exit(5)
for k,v in identity["Manifest"].items():
    if not (k != "OS" and k != "KernelCache" and k != "RestoreKernelCache" and k != "RestoreTrustCache" and k != "StaticTrustCache" and k != "BasebandFirmware"): continue
    dec = asn1.Decoder()
    dec.start(zip.read(v["Info"]["Path"]))
    #pretty_print(dec, stdout)
    dec.enter()
    if dec.read() == None: 
        print("Missing id 0")
        continue
    if dec.read() == None: 
        print("Missing id 1")
        continue
    if dec.read() == None: 
        print("Missing id 2")
        continue
    if dec.read() == None: 
        print("Missing id 3")
        continue
    if dec.eof():
        output[k] = {"Path": v["Info"]["Path"], "Encrypted": False}
        continue
    tag, value = dec.read()
    dec.start(value)
    dec.enter()
    dec.enter()
    dec.read()
    tag, ivenc = dec.read()
    tag, keyenc = dec.read()
    keys = None

    if 'PWND:[checkm8]' in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        keys = pwned.aes((ivenc + keyenc), usbexec.AES_DECRYPT, usbexec.AES_GID_KEY).encode('hex')
    else:
        device = dfuexec.PwnedDFUDevice()
        keys = device.aes_hex((ivenc + keyenc), dfuexec.AES_DECRYPT, dfuexec.AES_GID_KEY)
    output[k] = {"Path": v["Info"]["Path"], "Encrypted": True, "IV": keys[:32], "Key": keys[32:]}

file = open(argv[3], "w")
json.dump(output, file)
file.close()

if len(argv) < 5:
    print("Cleaning up...")
    remove("firmware.ipsw")

print("Keys saved to " + argv[3])