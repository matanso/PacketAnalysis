__author__ = 'matan'

import pcap


def intercept_packets(callback, filename):
    """
    :param callback: Invoked on all packets
    :param filename: Name of pcap file to read packets from
    :return: None
    """

    # Initialize pcapObject
    pcap_object = pcap.pcapObject()

    # Open pcap file for reading packets
    pcap_object.open_offline(filename)

    # Read all packets and call callback
    c = pcap_object.next()
    while c is not None:
        callback(*c)
        c = pcap_object.next()