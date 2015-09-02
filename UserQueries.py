__author__ = 'matan'

import IPUtils as Util
import PcapUtils
import time
import pcap


def handle_query(query, ip_dict, port_dict, ip_to_ip_dict, ip_port_dict):
    arr = query.split()
    if arr[0] == "list":
        list_all(ip_dict)
        print
        return

    # IP-specific queries
    try:
        ip = pcap.aton(arr[1])
    except:
        print("Couldn't parse IP address " + arr[1])
        return

    # Display all IPs that this IP has communicated with
    if arr[0] == "friends":
        for other in ip_dict[ip]:
            print(pcap.ntoa(other))
        print

    # List all live TCP sessions for IP
    if arr[0] == "live":
        list_live(ip, ip_dict, ip_to_ip_dict, ip_port_dict)


def list_live(ip, ip_dict, ip_to_ip_dict, ip_port_dict):
    for session in PcapUtils.get_live_sessions(ip, time.time(), ip_dict, ip_to_ip_dict, ip_port_dict):
        print(Util.tcp_session_tuple_to_str(session))


def list_all(ip_dict):
    for ip in ip_dict:
        print(pcap.ntoa(ip))


def interact(ip_dict, port_dict, ip_to_ip_dict, ip_port_dict):
    while True:
        handle_query(raw_input(), ip_dict, port_dict, ip_to_ip_dict, ip_port_dict)