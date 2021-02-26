"""GeoLookup Class"""


import time
import pprint

# Third Party
import requests

# Local imports
from zat.utils import cache


class GeoLookup(object):
    """GeoLookup: Query IPStack API (https://ipstack.com/) for Geographic information,
                 the class contains a Cache to minimize queries.

        Args:
            apikey (str): The API key to use for IPStack queries (default=None)
            summary (bool): Just return summary information for GeoLookup (default=True)
            max_cache_size (int): Maximum size of query cache (default=10000)
            max_cache_time (int): Time to keep query results in cache (default=30 days)
    """

    def __init__(self, apikey=None, summary=True, max_cache_size=10000, max_cache_time=30, throttle=True):
        """GeoLookup Init"""

        # Public API Key
        # Note: The key below is a low-volume public key. Please call this method with your own API key :)
        if apikey is None:
            print('Using public API Key: Please set apikey=<your key> when creating this class')
        pub_apikey = '7278776fac2f2c66b1c760c650c20e8e'
        self.known_ipstack_ips = ['158.85.167.221', '158.85.167.217', '158.85.167.201']
        self.apikey = apikey or pub_apikey
        self.summary = summary
        self.throttle = throttle

        # Create query cache
        seconds = max_cache_time*24*60*60  # Convert from days
        self.query_cache = cache.Cache(max_size=max_cache_size, timeout=seconds, load='zat_geo_cache')  # Convert to Seconds

    @property
    def size(self):
        return self.query_cache.size

    def query_ip(self, ip_address, verbose=False):
        """Query method for the IpStack Service
            Args:
               ip_address(str): The IP Address to be queried
        """

        # Is this a known IpStack ip address?
        if ip_address in self.known_ipstack_ips:
            return None

        # First check query cache
        cached = self.query_cache.get(ip_address)
        if cached:
            if verbose:
                print('Returning Cached Query Results')
            return cached

        # Not in cache so make the actual query
        url = 'http://api.ipstack.com/' + ip_address
        response = requests.post(url, params={'access_key': self.apikey})

        # Make sure we got a json blob back
        try:
            output = response.json()
        except ValueError:
            error_msg = 'No valid response, throttling and trying again...'
            if self.throttle:
                if verbose:
                    print(error_msg)
                time.sleep(30)
                return self.query_ip(ip_address)

            return {'error': error_msg}

        # Check for error or not-found
        if output['type'] is None:
            output = None
            self.query_cache.set(ip_address, output)
            return output

        # Summary removes 'location' info (flag, calling_code, languages, etc)
        if self.summary:
            del output['location']

        # Put results in Cache
        self.query_cache.set(ip_address, output)
        self.query_cache.persist()

        # Return results
        return output


# Unit test: Create the class and test it
def test():
    """geo_lookup.py test"""

    # Execute the worker (unit test)
    geo_lookup = GeoLookup(summary=False)
    output = geo_lookup.query_ip('73.26.145.66')
    print('\n<<< Unit Test FULL>>>')
    pprint.pprint(output)

    geo_lookup = GeoLookup()
    output = geo_lookup.query_ip('73.26.145.66')
    print('\n<<< Unit Test Summary>>>')
    pprint.pprint(output)
    output = geo_lookup.query_ip('123.4.5.6')
    print('\n<<< Unit Test Summary>>>')
    pprint.pprint(output)

    # Test Cache
    output = geo_lookup.query_ip('73.26.145.66')
    print('\n<<< Unit Test Cache>>>')
    pprint.pprint(output)

    # Test Size
    assert geo_lookup.size == 2

    # Test some error conditions
    output = geo_lookup.query_ip('123')
    print('\n<<< Unit Test Malformed IP Query>>>')
    pprint.pprint(output)


if __name__ == "__main__":
    test()
