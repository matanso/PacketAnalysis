__author__ = 'matan'

from socket import IPPROTO_TCP
import IPUtils as Util


def update_tcp_session(source_ip, destination_ip, source_port, destination_port, ip_port_dict, timestamp, tcp_flags):
    # Create dictionary keys
    key1 = Util.ip_port_make_key(source_ip, destination_ip, source_port, destination_port)
    key2 = Util.ip_port_make_key(destination_ip, source_ip, destination_port, source_port)

    # Parse TCP flags
    ack = tcp_flags & 0b00001000
    syn = tcp_flags & 0b01000000
    rst = tcp_flags & 0b00100000
    fin = tcp_flags & 0b10000000

    if fin or rst:  # Connection was terminated
        ip_port_dict[key1] = (timestamp, False)
        ip_port_dict[key2] = (timestamp, False)

    elif key1 in ip_port_dict:    # Session recorded in memory

        # Get the last state of this session
        prev_timestamp, is_active = ip_port_dict[key1]

        if not is_active:    # Session was active and was terminated.

            # Check if session was established again with same IPs and ports after termination. Note that if we missed
            # Syn/Ack response (on "revive") from the server, the session will be counted as inactive.
            if syn and ack and timestamp > prev_timestamp:     # Session "revived"
                ip_port_dict[key1] = (timestamp, True)
                ip_port_dict[key2] = (timestamp, True)

        # Update last timestamp, connection still active
        else:
            timestamp = max(prev_timestamp, timestamp)
            ip_port_dict[key1] = (timestamp, True)
            ip_port_dict[key2] = (timestamp, True)

    else:

        # Session not in memory. Check if session was established
        if ack or not syn:  # Connection established (SYN & ACK) or already exists (not SYN)
            ip_port_dict[key1] = (timestamp, True)
            ip_port_dict[key2] = (timestamp, True)


def load_packet(data, timestamp, ip_dict, port_dict, ip_to_ip_dict, ip_port_dict):
    # Parse addresses from IP header
    source_ip = data[12:16]
    destination_ip = data[16:20]

    # Insert IPs to IP dict
    ip_dict[source_ip].add(destination_ip)
    ip_dict[destination_ip].add(source_ip)

    # Create dictionary keys
    ip_key1 = Util.ip_to_ip_make_key(source_ip, destination_ip)
    ip_key2 = Util.ip_to_ip_make_key(destination_ip, source_ip)

    # Parse other info
    header_len = ord(data[0]) & 0x0f
    tcp_offset = 4 * header_len
    source_port = data[tcp_offset: tcp_offset + 2]
    destination_port = data[tcp_offset + 2: tcp_offset + 4]
    protocol = data[9]

    # insert ports into port_dict
    port_dict[source_ip].add(source_port)
    port_dict[destination_ip].add(destination_port)

    # Insert ports used into ip_to_ip_dict
    ip_to_ip_dict[ip_key1].add((source_port, destination_port, protocol))
    ip_to_ip_dict[ip_key2].add((destination_port, source_port, protocol))

    # Check if tcp
    if ord(protocol) == IPPROTO_TCP:
        tcp_flags = ord(data[33])
        update_tcp_session(source_ip, destination_ip, source_port, destination_port, ip_port_dict, timestamp, tcp_flags)