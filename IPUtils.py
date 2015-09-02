__author__ = 'matan'

import pcap
import struct


def ip_bytes_to_str(ip):
    """
    Converts a bytes representation of an ip to a string
    """
    return pcap.ntoa(struct.unpack('I', ip)[0])


def port_bytes_to_int(port):
    """
    Converts a bytes representation of a port to a short
    """
    return struct.unpack('H', port)[0]


def ip_str_to_bytes(ip):
    """
    Converts a string representation of an ip to a bytes object
    """
    return struct.pack('I', pcap.aton(ip))


def port_int_to_bytes(port):
    """
    Converts a short representation of a port to a bytes object
    """
    return struct.pack('H', port)


def tcp_session_tuple_to_str(tup):
    """

    :param tup: a tuple as a result of PcapUtils.get_live_sessions
    :return: A string
    """
    return pcap.ntoa(tup[0]) + ":" + str(tup[2]) + " --> " + \
           pcap.ntoa(tup[1]) + ":" + str(tup[3])


def ip_bytes_to_int(ip):
    return struct.unpack('I', ip)[0]


def ip_to_ip_make_key(ip1, ip2):
    """
    Creates a key for ip_to_ip_dict
    """
    return ip1, ip2


def ip_port_make_key(ip1, ip2, port1, port2):
    """
    Creates a key for ip_port_dict
    """
    return tuple(sorted([ip1, ip2, port1, port2]))