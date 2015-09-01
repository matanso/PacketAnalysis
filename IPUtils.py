__author__ = 'matan'

import pcap
import struct


def ip_bytes_to_str(ip):
    """
    Converts a bytes representation of an ip to a string
    """
    return pcap.ntoa(struct.unpack('i', ip)[0])


def port_bytes_to_int(port):
    return struct.unpack('H', port)[0]