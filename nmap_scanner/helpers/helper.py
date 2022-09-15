import re
import socket

def compare_old_new(old, new):
    """
    Returns a list of added ports and deleted ports.
            Parameters:
                old (list): open ports from previous scan
                new (list): open ports from current scan
            Returns:
                (added_ports, deleted ports): tuple of added and deleted ports
    """
    old_set = set(old)
    new_set = set(new)
    return list(new_set - old_set), list(old_set - new_set)


def validate_hostname(hostname):
    """
    Validate hostname.
            Parameters:
                hostname (str): hostname/IP address
            Returns:
                True if hostname is valid, False otherwise
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def scan_ports(hostname, start, end):
    """
    Returns open ports scanned.
            Parameters:
                hostname (str): hostname/IP address
                start (int): start of port range
                end (int): end of port range

            Returns:
                open_ports (list): list of open ports on this host
    """
    ip = socket.gethostbyname(hostname)
    open_ports = []

    for port in range(start, end+1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        result = s.connect_ex((hostname, port))
        if result == 0:
            open_ports.append(str(port))
        s.close()
    return open_ports