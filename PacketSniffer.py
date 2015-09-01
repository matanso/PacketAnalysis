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


def intercept_packets_live(callback, dev):
    """
    :param callback: Invoked on all packets
    :return: None
    """

    # Initialize pcapObject
    pcap_object = pcap.pcapObject()

    # Open device for reading packets
    pcap_object.open_live(dev, 1500, 0, 0)

    # Read packets and call callback
    c = pcap_object.next()
    while 1:
        if c is not None:
            callback(*c)
        c = pcap_object.next()