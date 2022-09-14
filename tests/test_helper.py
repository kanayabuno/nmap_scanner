### test helper functions
from nmap_scanner.helpers import helper
import nmap

def test_validate_hostname():
    assert helper.validate_hostname("localhost")
    assert helper.validate_hostname("google.com")
    assert helper.validate_hostname("google.com.")

    assert not helper.validate_hostname("google.com-")
    assert not helper.validate_hostname("google..com-")

def test_compare_old_new():
    old = {}
    new = {1, 2}

    added, deleted = helper.compare_old_new(old , new)
    assert added == [1, 2]
    assert deleted == []

    old = {1, 2}
    new = {}

    added, deleted = helper.compare_old_new(old , new)
    assert added == []
    assert deleted == [1, 2]

    old = {1, 2}
    new = {3, 4}

    added, deleted = helper.compare_old_new(old , new)
    assert added == [3, 4]
    assert deleted == [1, 2]

    old = {}
    new = {}

    added, deleted = helper.compare_old_new(old , new)
    assert added == []
    assert deleted == []

    old = {1}
    new = {1}

    added, deleted = helper.compare_old_new(old , new)
    assert added == []
    assert deleted == []

def library_nmap(hostname, start, end):
    open_ports = []

    nm = nmap.PortScanner()
    range = str(start) + "-" + str(end)
    nm.scan(hostname, range)
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = list(nm[host][proto].keys())
            if lport:
                lport.sort()
                for port in lport:
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.append(str(port))
    return open_ports

def test_scan_ports():
    hostname, start, end = "localhost", 0, 1000
    assert library_nmap(hostname, start, end) == helper.scan_ports(hostname, start, end)

    hostname, start, end = "google.com", 0, 1000
    assert library_nmap(hostname, start, end) == helper.scan_ports(hostname, start, end)