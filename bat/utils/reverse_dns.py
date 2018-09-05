"""ReverseDNS, Perform a reverse dns lookup on fields in the ip_field_list."""
from __future__ import print_function
import socket

# Local imports
from bat.utils import net_utils, cache


class ReverseDNS(object):
    """Perform a reverse dns lookup on fields in the ip_field_list."""

    def __init__(self, lookup_internal=False):
        """Initialize ReverseDNS Class"""
        self.ip_lookup_cache = cache.Cache(timeout=600)
        self.lookup_internal = lookup_internal

    def lookup(self, ip_address):
        """Try to do a reverse dns lookup on the given ip_address"""

        # Is this already in our cache
        if self.ip_lookup_cache.get(ip_address):
            domain = self.ip_lookup_cache.get(ip_address)

        # Is the ip_address local or special
        elif not self.lookup_internal and net_utils.is_internal(ip_address):
            domain = 'internal'
        elif net_utils.is_special(ip_address):
            domain = net_utils.is_special(ip_address)

        # Look it up at this point
        else:
            domain = self._reverse_dns_lookup(ip_address)

        # Cache it
        self.ip_lookup_cache.set(ip_address, domain)

        # Return the domain
        return domain

    @staticmethod
    def _reverse_dns_lookup(ip_address):
        """Perform the reverse DNS lookup

           Args:
               ip_address: the ip_address (as a str)
           Returns:
               the domain given by a reverse DNS request on the ip address
        """

        # Look it up
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            return 'nxdomain'


def test():
    """Test for ReverseDNS class"""
    dns = ReverseDNS()

    print(dns.lookup('192.168.0.1'))
    print(dns.lookup('8.8.8.8'))

    # Test cache
    print(dns.lookup('8.8.8.8'))


if __name__ == '__main__':
    test()
