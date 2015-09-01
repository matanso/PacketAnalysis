__author__ = 'matan'

import pcap
import struct


def ip_bytes_to_str(ip):
    """
    Converts a bytes representation of an ip to a string
    """
    return pcap.ntoa(struct.unpack('i', ip)[0])


def port_bytes_to_int(port):
    """
    Converts a bytes representation of a port to a short
    """
    return struct.unpack('H', port)[0]


def ip_str_to_bytes(ip):
    """
    Converts a string representation of an ip to a bytes object
    """
    return struct.pack('i', (pcap.aton(ip),))


def port_int_to_bytes(port):
    """
    Converts a short representation of a port to a bytes object
    """
    return struct.pack('H', (port,))