"""VTQuery Class"""

from __future__ import print_function
import collections
import time
import pprint

# Third Party
import requests

# Local imports
from bat.utils import cache


class VTQuery(object):
    """VTQuery: Will query VirusTotal for a sha, the class contains a Cache to avoid
                slamming duplicate queries.

        Args:
            apikey (str): The API key to use for VirusTotal queries (default=None)
            summary (bool): Just return summary information for VTQuery (default=True)
            max_cache_size (int): Maximum size of query cache (default=1000)
            max_cache_time (int): Time to keep query results in cache (default=60 minutes)
    """

    def __init__(self, apikey=None, summary=True, max_cache_size=1000, max_cache_time=60, throttle=True):
        """VTQuery Init"""

        # Public VT API Key
        # Note: The Virus Total key below is a low-volume public key.
        #       Please call this method with your own VT API key :)
        if apikey is None:
            print('Using public VT API Key: Please set apikey=<your key> when creating this class')
        pub_vt_apikey = 'ab0933e5b4d8032031bbce54b4170453e62c229dcf93fb99b0b80f09e415f809'
        self.apikey = apikey or pub_vt_apikey
        self.exclude = ['scan_id', 'md5', 'sha1', 'sha256', 'resource', 'response_code', 'permalink',
                        'verbose_msg', 'scans'] if summary else []
        self.throttle = throttle

        # Create query cache
        self.query_cache = cache.Cache(max_size=max_cache_size, timeout=max_cache_time*60)  # Convert to Seconds

    def query_file(self, file_sha, verbose=False):
        """Query the VirusTotal Service
            Args:
               file_sha (str): The file sha1 or sha256 hash
               url (str): The domain/url to be queried (default=None)
        """

        # Sanity check sha hash input
        if len(file_sha) not in [64, 40]:  # sha256 and sha1 lengths
            print('File sha looks malformed: {:s}'.format(file_sha))
            return {'file_sha': file_sha, 'malformed': True}

        # Call and return the internal query method
        return self._query('file', file_sha, verbose)

    def query_url(self, url, verbose=False):
        """Query the VirusTotal Service
            Args:
               url (str): The domain/url to be queried
        """
        # Call and return the internal query method
        return self._query('url', url, verbose)

    @property
    def size(self):
        return self.query_cache.size

    def _query(self, query_type, query_str, verbose=False):
        """Internal query method for the VirusTotal Service
            Args:
               query_type(str): The type of query (either 'file' or 'url')
               query_str (str): The file hash or domain/url to be queried
        """
        # First check query cache
        cached = self.query_cache.get(query_str)
        if cached:
            if verbose:
                print('Returning Cached VT Query Results')
            return cached

        # Not in cache so make the actual query
        if query_type == 'file':
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                    params={'apikey': self.apikey, 'resource': query_str, 'allinfo': 1})
        else:
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                                     params={'apikey': self.apikey, 'resource': query_str, 'allinfo': 1})

        # Make sure we got a json blob back
        try:
            vt_output = response.json()
        except ValueError:
            error_msg = 'VirusTotal no valid response, throttling and trying again...'
            if self.throttle:
                if verbose:
                    print(error_msg)
                time.sleep(30)
                return self._query(query_type, query_str)

            return {'vt_error': error_msg}

        # Check for not-found
        if not vt_output or vt_output['response_code'] == 0:
            output = {'query': query_str, 'not_found': True}
            self.query_cache.set(query_str, output)
            return output

        # Exclude some fields (if summary=True)
        output = {field: vt_output[field] for field in vt_output.keys() if field not in self.exclude}

        # Put the file sha in the output
        output['query'] = query_str

        # Organize the scans fields
        scan_results = collections.Counter()
        for scan in vt_output['scans'].values():
            if 'result' in scan:
                if scan['result']:
                    scan_results[scan['result']] += 1
        output['scan_results'] = scan_results.most_common(5)

        # Pull results in Cache
        self.query_cache.set(query_str, output)

        # Return results
        return output


# Unit test: Create the class and test it
def test():
    """vt_query.py test"""

    # Execute the worker (unit test)
    vt_query = VTQuery(summary=False)
    output = vt_query.query_file('eb107c004e6e1bbd3b32ad7961661bbe28a577b0cb5dac4cfd518f786029cb95')
    print('\n<<< Unit Test Full>>>')
    pprint.pprint(output)
    vt_query = VTQuery()
    output = vt_query.query_file('4ecf79302ba0439f62e15d0526a297975e6bb32ea25c8c70a608916a609e5a9c')
    print('\n<<< Unit Test Summary>>>')
    pprint.pprint(output)

    # Test queries on domain names
    output = vt_query.query_url('amazon.co.uk.security-check.ga')
    print('\n<<< Unit Test Domain Names>>>')
    pprint.pprint(output)

    # Test Cache
    output = vt_query.query_file('4ecf79302ba0439f62e15d0526a297975e6bb32ea25c8c70a608916a609e5a9c')
    print('\n<<< Unit Test Cache>>>')
    pprint.pprint(output)

    # Test Size
    assert vt_query.size == 2

    # Test some error conditions
    output = vt_query.query_file('123')
    print('\n<<< Unit Test Malformed SHA HASH>>>')
    pprint.pprint(output)
    output = vt_query.query_file('123f79302ba0439f62e15d0526a297975e6bb32ea25c8c70a608916a609e5a9c')
    print('\n<<< Unit Test Not Found>>>')
    pprint.pprint(output)


if __name__ == "__main__":
    test()
