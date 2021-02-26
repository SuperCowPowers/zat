"""Network utilities that might be useful"""


import socket
import binascii
import ipaddress


def mac_to_str(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % b for b in address)


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
    """Determine if the address is an internal ip address"""
    return ipaddress.ip_address(ip_address).is_private


def is_special(ip_address):
    """Determine if the address is SPECIAL
       Note: This is super bad, improve it
    """
    special = {'224.0.0.251': 'multicast_dns',
               'ff02::fb': 'multicast_dns'}
    return special[ip_address] if ip_address in special else False


def traffic_direction(conn_row):
    """Determine the direction of the connection traffic (takes a conn.log row)"""

    # First try to use the local orig/resp fields
    if conn_row.get('local_orig') and conn_row.get('local_resp'):
        local_orig = conn_row['local_orig']
        local_resp = conn_row['local_resp']
    else:
        # Well we don't have local orig/resp fields so use RFC1918 logic
        local_orig = ipaddress.ip_address(conn_row['id.orig_h']).is_private
        local_resp = ipaddress.ip_address(conn_row['id.resp_h']).is_private

    # Determine north/south or internal traffic
    if (not local_orig) and local_resp:
        return 'incoming'
    if local_orig and not local_resp:
        return 'outgoing'

    # Neither host is in the allocated private ranges
    if ipaddress.ip_address(conn_row['id.orig_h']).is_multicast or \
       ipaddress.ip_address(conn_row['id.resp_h']).is_multicast:
        return 'multicast'

    # Both hosts are internal
    return 'internal'


def test_utils():
    """Test the utility methods"""

    print(mac_to_str(b'\x01\x02\x03\x04\x05\x06'))
    assert mac_to_str(b'\x01\x02\x03\x04\x05\x06') == '01:02:03:04:05:06'
    assert str_to_mac('01:02:03:04:05:06') == b'\x01\x02\x03\x04\x05\x06'
    my_mac = b'\x01\x02\x03\x04\x05\x06'
    my_str = mac_to_str(my_mac)
    assert str_to_mac(my_str) == my_mac
    print(inet_to_str(b'\x91\xfe\xa0\xed'))
    assert inet_to_str(b'\x91\xfe\xa0\xed') == '145.254.160.237'
    assert str_to_inet('145.254.160.237') == b'\x91\xfe\xa0\xed'

    # IPV6 for Google DNS server
    google_dns = '2001:4860:4860::8888'
    google_inet = b' \x01H`H`\x00\x00\x00\x00\x00\x00\x00\x00\x88\x88'
    assert str_to_inet(google_dns) == google_inet

    # Various methods
    assert is_internal('10.0.0.1')
    assert is_internal('222.2.2.2') is False
    assert is_special('224.0.0.251')
    assert is_special('224.0.0.252') is False
    print('Success!')


if __name__ == '__main__':
    test_utils()
