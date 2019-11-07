"""Network utilities that might be useful"""
from __future__ import print_function

import socket
import binascii

# Local imports
from zat.utils import compat


def mac_to_str(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat.ord(b) for b in address)


def str_to_mac(mac_string):
    """Convert a readable string to a MAC address

           Args:
               mac_string (str): a readable string (e.g. '01:02:03:04:05:06')
           Returns:
               str: a MAC address in hex form
        """
    sp = mac_string.split(':')
    mac_string = ''.join(sp)
    return binascii.unhexlify(mac_string)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def str_to_inet(address):
    """Convert an a string IP address to a inet struct

        Args:
            address (str): String representation of address
        Returns:
            inet: Inet network address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_pton(socket.AF_INET, address)
    except socket.error:
        return socket.inet_pton(socket.AF_INET6, address)


def is_internal(ip_address):
    """Determine if the address is an internal ip address
       Note: This is super bad, improve it
    """
    # Local networks 10.0.0.0/8, 172.16.0.0/12, '192.168.0.0/16
    local_nets = '10.', '172.16.', '192.168.', '169.254', 'fd', 'fe80::'
    return any([ip_address.startswith(local) for local in local_nets])


def is_special(ip_address):
    """Determine if the address is SPECIAL
       Note: This is super bad, improve it
    """
    special = {'224.0.0.251': 'multicast_dns',
               'ff02::fb': 'multicast_dns'}
    return special[ip_address] if ip_address in special else False


def test_utils():
    """Test the utility methods"""

    print(mac_to_str(b'\x01\x02\x03\x04\x05\x06'))
    assert mac_to_str(b'\x01\x02\x03\x04\x05\x06') == '01:02:03:04:05:06'
    assert str_to_mac('01:02:03:04:05:06') == b'\x01\x02\x03\x04\x05\x06'
    foo = b'\x01\x02\x03\x04\x05\x06'
    bar = mac_to_str(foo)
    assert str_to_mac(bar) == foo
    print(inet_to_str(b'\x91\xfe\xa0\xed'))
    assert inet_to_str(b'\x91\xfe\xa0\xed') == '145.254.160.237'
    assert str_to_inet('145.254.160.237') == b'\x91\xfe\xa0\xed'
    assert is_internal('10.0.0.1')
    assert is_internal('222.2.2.2') is False
    assert is_special('224.0.0.251')
    assert is_special('224.0.0.252') is False
    print('Success!')


if __name__ == '__main__':
    test_utils()
