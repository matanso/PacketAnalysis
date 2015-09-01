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
    return struct.pack('i', pcap.aton(ip))


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
    return ip_bytes_to_str(tup[0]) + ":" + str(port_bytes_to_int(tup[2])) + " --> " + \
           ip_bytes_to_str(tup[1]) + ":" + str(port_bytes_to_int(tup[3]))


def ip_to_ip_make_key(ip1, ip2):
    return ip1 + ip2


def ip_port_make_key(ip1, ip2, port1, port2):
    return ip1 + ip2 + port1 + port2