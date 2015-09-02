__author__ = 'matan'


from socket import IPPROTO_TCP
import IPUtils as Util

TCP_SESSION_TIMEOUT = 86400


def seen_before(ip, ip_dict):
    """
    :param ip: Assuming IP in int
    :return: Boolean
    """
    return ip in ip_dict


def communicated(source_ip, destination_ip, ip_dict):
    """
    :param source_ip: First IP as int
    :param destination_ip: Second IP as int
    :return: Boolean
    """

    return destination_ip in ip_dict[source_ip]


def communicated_on_port(ip, port, port_dict):
    """
    :param ip: IP as int
    :param port: (Port, protocol) Both in int
    :return: Boolean
    """
    return port in port_dict[ip]


def communicated_with_ip_on_port(source_ip, destination_ip, port, ip_to_ip_dict):
    """
    :param source_ip: First IP as int
    :param destination_ip: Second IP as int
    :param port: (Port, protocol) both as int
    :return: Boolean
    """

    # Get all ports used for communication between 2 IPs
    # TODO: Optimize with new dict that maps 2 IPs -> set(port)?
    ports = ip_to_ip_dict[Util.ip_to_ip_make_key(source_ip, destination_ip)]
    port_num, curr_protocol = port
    return any(port_num == source_port and curr_protocol == protocol for source_port, destination_port, protocol in ports)


def get_live_sessions(ip_address, curr_timestamp, ip_dict, ip_to_ip_dict, ip_port_dict):
    """
    Get all live TCP sessions for an IP address

    :param ip_address: IP as int
    :return: list(tuples)
    """

    # Iterate over all IPs
    res = []
    for other_ip in ip_dict[ip_address]:

        # Iterate over all sessions between the IPs
        for (source_port, destination_port, protocol) in ip_to_ip_dict[Util.ip_to_ip_make_key(ip_address, other_ip)]:

            # Generate dictionary key
            key = Util.ip_port_make_key(ip_address, other_ip, source_port, destination_port)

            # Check if session was a TCP session and if it was established
            if protocol == IPPROTO_TCP and key in ip_port_dict:

                # Retrieve session data
                prev_timestamp, is_active = ip_port_dict[key]

                # Check if session wasn't terminated or timed out
                if is_active and curr_timestamp - prev_timestamp < TCP_SESSION_TIMEOUT:
                    res += [(ip_address, other_ip, source_port, destination_port)]
    return res