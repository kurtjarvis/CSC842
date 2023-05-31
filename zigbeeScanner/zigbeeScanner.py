#!/usr/bin/env python3
# 
# Author: Kurt Jarvis
# Created: 31 May 2023
# Class: CSC-842
# Purpose: A scanner to find zigbee devices on the network

# import block
import pyshark
import datetime as DT
import sys
import os
import argparse
from pathlib import Path
import re

## global vars
mac_dict = {}
# create a set of unique mac addresses as we parse all this fun stuff
mac_addresses = set()
unique_pans = set()
unique_devices = set()

# loads single pcap into all of its frames
def parsePcap(pcap):
    frames = pyshark.FileCapture(pcap) #initialize
    frames.load_packets()
    return frames
  
# function to print dictionary items that are not empty
def print_dict(dict, f):
    if dict is None or f is None:
        return
    for key, value in dict.items():
        if value != "":
            print("  " + key + " = " + str(value), file=f)
    print("", file=f)
    return

# Out of all the things in this layer, the only thing we really want is who is sending this message!
def parseNwkLayer(frame):
    # init empty vars
    if hasattr(frame['ZBEE_NWK'],'zbee_sec_src64'):
        src64 = frame['ZBEE_NWK'].zbee_sec_src64
        #dictionary lookup for the manufacturer name
        src64_name = str(src64.upper())
        while len(src64_name) >= 8:
            if src64_name in mac_dict:
                break
            src64_name = src64_name[:-1]
        if src64_name in mac_dict:
            src64_name = mac_dict[src64_name] # longest match only
        else:
            src64_name = ""
        if "\t" in src64_name: #strip extra description
            src64_name, throw = src64_name.split("\t",1)
    nwk_info = {
        "nwk_extended_src64": src64,
        "nwk_manufacturer": src64_name
    }
    return nwk_info

# Parse a frame layer and see if we have some data in it we want.
# really in the frame layer, we don't want anything because it doesn't help us with identification
def parseFrame(frame):
    nwk_info = None
    if 'ZBEE_NWK' in str(frame.layers):
        nwk_info = parseNwkLayer(frame)
    return nwk_info

def pullUniqueValues(frame):
    addMac(frame)
    addDev(frame)
    # TODO more unique attributes
    return

# if the mac address is available, pull it out into our set for unique devices
def addMac(frame):
    #import pdb; pdb.set_trace()
    if frame is not None and frame["nwk_extended_src64"] != "":
        mac_addresses.add(frame["nwk_extended_src64"])
    return

def addDev(frame):
    if frame is not None and frame["nwk_extended_src64"] != "":
        unique_devices.add(str(frame["nwk_extended_src64"]))
    return

# Now we can read in the config file IF the choice was mac?
def uniqueMacAddresses(macfile, mac_addresses, f):
    print("Unique MAC Addresses", file=f)
    for a in mac_addresses:
        key = str(a.upper())
        while len(a) >= 8:
            if key in mac_dict:
                break
            key = key[:-1]
        if key not in mac_dict:
            print("The src %s cannot be resolved from %s" % (a, macfile), file=f )
            break
        values = mac_dict[key].split("\t")
        # this file has an optional long string that has more descriptions
        print("Device, %s, %s" % (a, values[-1]), file=f )
    return

# Parse out the MAC file and save it in a dictionary for lookup later
def macFile2Dict(macfile):
    macFile = open(macfile)
    for line in macFile:
        if re.search("^#", line.strip()) or len(line.strip()) < 5:
            continue
        key,value = line.split("\t",1)
        if "/" in key:
            key,throw = key.split("/")
        mac_dict[key] = value.strip()
    return
        
#python def for main
def main():
    # Set up the arguments
    parser = argparse.ArgumentParser(description="Zigbee parser")
    parser.add_argument('-p', '--pcap_file', help="PCAP filename to read in and parse",
                        nargs='+')
    parser.add_argument("-o", "--outfile", dest='outfile',
                        help="file to save the output")    
    parser.add_argument("-q", "--quiet", default=False, action="store_true", help="hide processing messages")
 
    parser.add_argument("-m", "--macfile", dest='macfile',
                        help="file that contains the mac addresses to vendor names from wireshark github")
    parser.add_argument("-l", "--live", help="using the device provided, attempts to do live data captures until exiting: only if the -p option is not provided")
    options = parser.parse_args()
    f = None
    #Validations
    # Set up the ability to use output files
    if options.outfile is not None:
        f = open(options.outfile, 'w')
    elif options.quiet is True:
        f = None
    else:
        f = sys.stdout
    # vendor names into searchable dictionary
    if options.macfile is None:
        #default to the included
        options.macfile = "github-MAC-manufactor_codes.txt"
    macFile2Dict(options.macfile)

    if options.pcap_file: # else live capture
        # frame definitions if from pcap(s)
        #object is dictionary based on frame
        for pcap in options.pcap_file:
            myPath = Path(pcap)
            if not myPath.is_file(): 
                print("Unable to find %s, please check the file path" % pcap)
                continue
            if pcap:
                frames = parsePcap(pcap)
                for frame in frames:
                    frameinfo = parseFrame(frame)
                    print_dict(frameinfo, f)
                    pullUniqueValues(frameinfo)
    # frame definition if from live capture
    #object is dictionary based on frame
    elif options.live:
        if not Path(options.live).is_char_device():
            print("Unable to verify the character device: %s, please check and provide a device full path" % options.live)
            return 2
        try:
            # this can also take a BPF filter, so we could go all command-line editable!
            cap = pyshark.LiveCapture(interface=options.live, output_file=options.outfile)
        except Exception:
            print("Cannot start capturing events with tshark with interface: %s, troubleshoot and try again" % options.live)
            return 3
        try:
            for packet in cap.sniff_continuously():
                frameinfo = parseFrame(packet)
                pullUniqueValues(frameinfo)
                print_dict(frameinfo, f)
        except Exception:
            print("Error occurred while reading, exiting")
            cap.close()
    else:
        print("No path for capture has been specified.")
        parser.print_help()
        return 4
    # so at this point we have the mac addresses all in a set (no duplicates)
    uniqueMacAddresses(options.macfile, mac_addresses, f)
    print()
    # If we were writing to a file, close it and reset the stdout
    if f is not sys.stdout and f is not None:
        f.close()
    return 0

# Main instantiation
if __name__ == "__main__":
   main()
