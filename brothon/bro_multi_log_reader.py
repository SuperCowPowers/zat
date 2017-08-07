"""BroLogReader: This class reads in various Bro IDS logs. The class inherits from
                 the FileTailer class so it supports the following use cases:
                   - Read contents of a Bro log file        (tail=False)
                   - Read contents + 'tail -f' Bro log file (tail=True)
       Args:
            filepath (str): The full path the file (/full/path/to/the/file.txt)
            delimiter (str): The delimiter in the Bro IDS logs (default='\t')
            tail (bool): Do a dynamic tail on the file (i.e. tail -f) (default=False)
"""
from __future__ import print_function
import os
import time
import datetime
import glob
import gzip
import tempfile
import shutil

# Local Imports
from brothon import bro_log_reader


class BroMultiLogReader(object):
    """BroMultiLogReader: This class reads in multiple Bro IDS logs.
           Args:
                filepath (str): The full path the file (/full/path/to/the/file.txt) can be a
                                glob (e.g dns*.log) or a gzip file (e.g. dns.log.gz)
    """

    def __init__(self, filepath):
        """Initialization for the BroMultiLogReader Class"""

        # The filepath may be a glob pattern
        self._files = glob.glob(filepath)

    def readrows(self):
        """The readrows method reads in the header of the Bro log and
            then uses the parent class to yield each row of the log file
            as a dictionary of {key:value, ...} based on Bro header.
        """

        # For each file (may be just one) create a BroLogReader and use it
        for self._filepath in self._files:

            # Check if the file is zipped
            if self._filepath.endswith('.gz'):
                tmp = tempfile.NamedTemporaryFile(delete=False)
                with gzip.open(self._filepath, 'rb') as f_in, open(tmp.name, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

                # Set the file path to the new temp file
                self._filepath = tmp.name

            # Create a BroLogReader
            reader = bro_log_reader.BroLogReader(self._filepath)
            for row in reader.readrows():
                yield row

            # Clean up any temp files
            try:
                os.remove(tmp.name)
                print('Removed temporary file {:s}...'.format(tmp.name))
            except:
                pass

def test():
    """Test for BroLogReader Python Class"""
    from brothon.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')

    # For each file, create the Class and test the reader
    files = ['http.log.gz', 'dhcp*.log', 'dhcp*.log.gz']
    for bro_log in files:
        test_path = os.path.join(data_path, bro_log)
        print('Opening Data File: {:s}'.format(test_path))
        reader = BroMultiLogReader(test_path)
        for line in reader.readrows():
            print(line)
    print('Tests successful!')

if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
