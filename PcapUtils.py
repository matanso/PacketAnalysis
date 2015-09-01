__author__ = 'matan'


from socket import IPPROTO_TCP
import IPUtils as Util

TCP_SESSION_TIMEOUT = 864000000


def seen_before(ip, ip_dict):
    """
    :param ip: Assuming IP in bytes
    :return: Boolean
    """
    return ip in ip_dict


def communicated(source_ip, destination_ip, ip_dict):
    """
    :param source_ip: First IP as bytes
    :param destination_ip: Second IP as bytes
    :return: Boolean
    """

    return destination_ip in ip_dict[source_ip]


def communicated_on_port(ip, port, port_dict):
    """
    :param ip: IP in bytes
    :param port: Port in Bytes
    :return: Boolean
    """
    return port in port_dict[ip]


def communicated_with_ip_on_port(source_ip, destination_ip, port, ip_to_ip_dict):
    """
    :param source_ip: First IP as bytes
    :param destination_ip: Second IP as bytes
    :param port: Port as bytes
    :return: Boolean
    """
    return port == ip_to_ip_dict[source_ip + destination_ip][0]


def get_live_sessions(ip_address, curr_timestamp, ip_dict, ip_to_ip_dict, ip_port_dict):
    """

    :param ip_address: IP as bytes
    :return: list(tuples)
    """

    # Iterate over all IPs
    res = []
    for other_ip in ip_dict[ip_address]:
        # Iterate over all sessions
        for session in ip_to_ip_dict[ip_address + other_ip]:
            key = ip_address + other_ip + session[0] + session[1]
            if ord(session[2]) == IPPROTO_TCP and key in ip_port_dict:     # This was a tcp session
                session_data = ip_port_dict[key]
                if session_data[1] and curr_timestamp - session_data[0] < TCP_SESSION_TIMEOUT:
                    res += [(ip_address, other_ip, session[0], session[1])]
    return res