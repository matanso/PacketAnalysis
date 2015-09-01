__author__ = 'matan'

import PacketSniffer
import PacketParser
import PcapUtils
import time
import collections
import IPUtils as Util
import threading
import UserQueries
import sys

# Denotes whether to capture live packets or not
live = True

'''
This code uses the following variables:
IP dict - a dict that maps an IP to a set of IPs it has communicated with
port_dict - a dict that maps an IP to a set of ports it has communicated on
IP_to_IP dict - a dict that maps the expression source-IP + destination-IP to a set of (source_port, destination_port, protocol)
IP_port_dict - a dict that maps the expression source-IP + destination-IP + source_port + destination_port to (timestamp, isActive)
'''

# Initialize data variables
ip_dict = collections.defaultdict(set)
port_dict = collections.defaultdict(set)
ip_to_ip_dict = collections.defaultdict(set)
ip_port_dict = {}


def callback(packet_length, data, timestamp):
    PacketParser.load_packet(data[14:], timestamp, ip_dict, port_dict, ip_to_ip_dict, ip_port_dict)

if live:
    # Load packets into memory in different thread
    intercept_thread = threading.Thread(target=PacketSniffer.intercept_packets_live, args=(callback, "eth0"))
    intercept_thread.setDaemon(True)
    intercept_thread.start()
    try:
        UserQueries.interact(ip_dict, port_dict, ip_to_ip_dict, ip_port_dict)
    except KeyboardInterrupt:
        sys.exit()

else:
    PacketSniffer.intercept_packets(callback, "packets/smallFlows.pcap")
    # Insert code for packets here