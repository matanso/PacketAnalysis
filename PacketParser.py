__author__ = 'matan'

from socket import IPPROTO_TCP


def update_tcp_session(source_ip, destination_ip, source_port, destination_port, ip_port_dict, timestamp, tcp_flags):
    # Create dictionary keys
    key1 = source_ip, destination_ip, source_port, destination_port
    key2 = destination_ip, source_ip, destination_port, source_port

    if key1 in ip_port_dict:
        value = ip_port_dict[key1]
        if not value[1]:
            return

        # Parse TCP flags
        rst = tcp_flags & 0b00100000
        fin = tcp_flags & 0b10000000

        if rst or fin:  # Connection terminated
            ip_port_dict[key1] = (0, False)
            ip_port_dict[key2] = (0, False)
            return

        # Update last timestamp, connection still active

        timestamp = max(value[0], timestamp)
        ip_port_dict[key1] = (timestamp, True)
        ip_port_dict[key2] = (timestamp, True)
        return

    # Parse TCP flags
    ack = tcp_flags & 0b00001000
    syn = tcp_flags & 0b01000000

    if not syn or ack:  # Connection established (SYN & ACK) or exists (not syn)
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
    ip_str = source_ip + destination_ip
    other_ip_str = destination_ip + source_ip

    # Parse other info
    source_port = data[20:22]
    destination_port = data[22:24]
    protocol = data[9]

    # insert ports into port_dict
    port_dict[source_ip].add(source_port)
    port_dict[destination_ip].add(destination_port)

    # Insert ports used into ip_to_ip_dict
    ip_to_ip_dict[ip_str].add((source_port, destination_port, protocol))
    ip_to_ip_dict[other_ip_str].add((destination_port, source_port, protocol))

    # Check if tcp
    if ord(protocol) == IPPROTO_TCP:
        tcp_flags = ord(data[33])
        update_tcp_session(source_ip, destination_ip, source_port, destination_port, ip_port_dict, timestamp, tcp_flags)