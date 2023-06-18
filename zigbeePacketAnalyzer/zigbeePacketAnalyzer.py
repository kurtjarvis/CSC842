#!/usr/bin/python3
# 
# Author: Kurt Jarvis
# Created: 14 June 2023
# Class: CSC-842
# Purpose: A zigbee pcap analyzer to process packets and see what is actually in the data.
# This is a clone of a previous student's work that I cloned and adopted for ZigBee. 
# All credits to https://github.com/tadiaz/DSU for starting this tool!
# 
import sys
import argparse
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm                   # progress meter for CLI display
import matplotlib.pyplot as plt
import numpy as np


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# I really want to change this order so that it uses the PcapReader instead of reading it all into memory.
# When I tried, it breaks the "tabulate" functionality because we really don't know how much data is coming.
# Need to think more about this design.
def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets

# this needs to extract the packet information.
def extract_packet_data(packets):
    packet_data = []

    # this code processes the TCP/IP packets
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size})
        elif "Dot15d4" in str(packet.layers):
            # Must be a 802.15.4 packet, let's process it and extract what we want
            if "Dot15d4Data" in str(packet.layers):
                packet_data.append({"src_ip": str(packet["Dot15d4Data"].src_addr), 
                                    "dst_ip": str(packet["Dot15d4Data"].dest_addr), 
                                    "protocol": 100, 
                                    "size": len(packet["Dot15d4Data"])
                                    })
            elif "Dot15d4Beacon" in str(packet.layers):
                packet_data.append({"src_ip": "0", 
                                    "dst_ip": "0", 
                                    "protocol": 101, 
                                    "size": len(packet["Dot15d4FCS"]),
                                    "panid" : str(packet["Dot15d4Beacon"].src_panid)
                                    })
            elif "Dot15d4Cmd" in str(packet.layers):
                packet_data.append({"src_ip": "0", 
                                    "dst_ip": str(packet["Dot15d4Cmd"].dest_addr), 
                                    "protocol": 102, 
                                    "size": len(packet["Dot15d4FCS"])
                                    })
            elif "Dot15d4FCS" in str(packet.layers):
                packet_data.append({"src_ip": "0", 
                                    "dst_ip": "0", 
                                    "protocol": 103, 
                                    "size": len(packet["Dot15d4FCS"])
                                    })
            else:
                print("Unknown packet")
                
    return pd.DataFrame(packet_data)

# have to expand this out for Zigbee, which is really undefined in this case. Do we wanna do that?
def protocol_name(number):
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 100: 'ZigbeeData', 101: 'ZigbeeBeacon', 102: 'ZigbeeCmd', 103: 'FCS'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts.index = protocol_counts.index.map(protocol_name)

    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()

    protocol_frequency = df["protocol"].value_counts()
    protocol_frequency.index = protocol_frequency.index.map(protocol_name)

    protocol_counts_df = pd.concat([protocol_frequency, protocol_counts], axis=1).reset_index()
    protocol_counts_df.columns = ["Protocol", "Count", "Percentage"]

    ip_communication_protocols = df.groupby(["src_ip", "dst_ip", "protocol"]).size().reset_index()
    ip_communication_protocols.columns = ["Source IP", "Destination IP", "Protocol", "Count"]
    ip_communication_protocols["Protocol"] = ip_communication_protocols["Protocol"].apply(protocol_name)


    ip_communication_protocols["Percentage"] = ip_communication_protocols.groupby(["Source IP", "Destination IP"])["Count"].apply(lambda x: x / x.sum() * 100)

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

# This really isn't applicable in ZigBee, but I'm researching if it really can be without the network key...
def extract_packet_data_security(packets):
    packet_data = []

    for packet in tqdm(packets, desc="Processing packets for port scanning activity", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)

            if TCP in packet:
                dst_port = packet[TCP].dport
            else:
                dst_port = 0

            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size, "dst_port": dst_port})

    return pd.DataFrame(packet_data)

def detect_port_scanning(df,port_scan_threshold):
    
    # if this is zigbee data, it really doesn't apply here
    if df.empty:
        return
    
    # Group packets by source IP and destination port
    port_scan_df = df.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
    
    # Count the unique ports for each source IP
    unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
    
    # Check for a large number of packets to different ports on a single IP address
    potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= port_scan_threshold]
    ip_addresses = potential_port_scanners['src_ip'].unique()
    
    if len(ip_addresses) > 0:
        logger.warning(f"Potential port scanning detected from IP addresses: {', '.join(ip_addresses)}")


def print_results(total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols):
    # Convert bandwidth to Mbps or Gbps
    if total_bandwidth < 10**9:
        bandwidth_unit = "Mbps"
        total_bandwidth /= 10**6
    else:
        bandwidth_unit = "Gbps"
        total_bandwidth /= 10**9

    logger.info(f"Total bandwidth used: {total_bandwidth:.2f} {bandwidth_unit}")
    logger.info("\nProtocol Distribution:\n")
    logger.info(tabulate(protocol_counts_df, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
    logger.info("\nTop IP Address Communications:\n")
    logger.info(tabulate(ip_communication_table, headers=["Source IP", "Destination IP", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))

    logger.info("\nShare of each protocol between IPs:\n")
    logger.info(tabulate(ip_communication_protocols, headers=["Source IP", "Destination IP", "Protocol", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))

def plot_all_graphs(protocol_counts, ip_communication_protocols, directory='./'):
    fig, ax = plt.subplots()
    items = []
    counts = []
    for i in range(len(protocol_counts.values.tolist())):
        items.append(protocol_counts.values.tolist()[i][0])
        counts.append(protocol_counts.values.tolist()[i][1])
    ax.pie(counts, labels=items)
    fig.savefig(directory + 'my_plot.png')
    items.clear()
    counts.clear()
    fig2, ax2 = plt.subplots(figsize=(6, 5))
    for i in range(len(ip_communication_protocols.values.tolist())):
        items.append(str(ip_communication_protocols.values.tolist()[i][0]) + " to " + str(ip_communication_protocols.values.tolist()[i][1]))
        counts.append(ip_communication_protocols.values.tolist()[i][3])
    theme = plt.get_cmap('twilight')
    ax2.set_prop_cycle("color", [theme(1. * i / len(counts)) for i in range(len(counts))])
    ax2.pie(counts, startangle=90)
    fig2.subplots_adjust(0.5,0,1.2,1)
    size = sum(counts)
    plt.legend(
        loc='upper left',
        labels=['%s, %1.1f%%' % (
        l, (float(s) / size) * 100) for l, s in zip(items, counts)],
        prop={'size': 9},
        bbox_to_anchor=(0.0, 1),
        bbox_transform=plt.gcf().transFigure
    )
    fig2.savefig(directory + 'my_plot2.png', bbox_inches='tight')


def main(pcap_file,port_scan_threshold, directory='./'):
    packets = read_pcap(pcap_file)
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols = analyze_packet_data(df)
    plot_all_graphs(protocol_counts, ip_communication_protocols, directory)
    print_results(total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols)
    df = extract_packet_data_security(packets)
    detect_port_scanning(df,port_scan_threshold)

# argument Parser
def parseArguments(valid_choices):
    # Set up the arguments
    parser = argparse.ArgumentParser(description="packet analyzer")
    parser.add_argument('-t', '--type', default='tcp', const='all', nargs='?',
                        choices=valid_choices,
                        help='types of packets to process (default: %(default)s)')
    parser.add_argument('-d', '--directory', help="directory to save the files to", default='./')
    parser.add_argument('pcap_file', help="file to read from")
    parser.add_argument('port_scan_threshold', type=int, choices=range(5, 500), help="port scan threshold value", default=100, nargs='?')
    return parser.parse_args()

if __name__ == "__main__":
    
    # Have to tell scapy which type of packet this is for 802.15.4
    scapy.config.conf.dot15d4_protocol = "zigbee"
    valid_choices = ['tcp', 'zigbee', 'all']
    parser = parseArguments(valid_choices)

    main(parser.pcap_file, parser.port_scan_threshold, parser.directory)
