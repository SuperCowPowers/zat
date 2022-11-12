"""ZeekMultiLogReader: This class reads in multiple Zeek logs"""

import os
import glob
import gzip
import tempfile

# Local Imports
from zat import zeek_log_reader


class ZeekMultiLogReader(object):
    """ZeekMultiLogReader: This class reads in multiple Zeek logs.
           Args:
                filepath (str): The full path the file (/full/path/to/the/file.txt) can be a
                                glob (e.g. dns*.log) or a gzip file (e.g. dns.log.gz)
    """

    def __init__(self, filepath):
        """Initialization for the ZeekMultiLogReader Class"""

        # The filepath may be a glob pattern
        self._files = glob.glob(filepath)

    def readrows(self):
        """The readrows method simply 'combines' the rows of multiple files OR
           gunzips the file and then reads the rows
        """

        # For each file (maybe just one) create a ZeekLogReader and use it
        for _filepath in self._files:

            # Check if the file is zipped
            tmp = None
            if _filepath.endswith('.gz'):
                tmp = tempfile.NamedTemporaryFile(delete=False)
                with gzip.open(_filepath, 'rb') as f_in, open(tmp.name, 'wb') as f_out:
                    try:
                        for line in f_in:
                            f_out.write(line)
                    except Exception as exc:
                        print(f'Exception in {_filepath} : {exc}')

                # Set the file path to the new temp file
                _filepath = tmp.name

            # Create a ZeekLogReader
            reader = zeek_log_reader.ZeekLogReader(_filepath)
            for row in reader.readrows():
                yield row

            # Clean up any temp files
            try:
                if tmp:
                    os.remove(tmp.name)
                    print('Removed temporary file {:s}...'.format(tmp.name))
            except IOError:
                pass


def test():
    """Test for ZeekMultiLogReader Python Class"""
    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')

    # For each file, create the Class and test the reader
    files = ['http.log.gz', 'dhcp*.log', 'dhcp*.log.gz']
    for zeek_log in files:
        test_path = os.path.join(data_path, zeek_log)
        print('Opening Data File: {:s}'.format(test_path))
        reader = ZeekMultiLogReader(test_path)
        for line in reader.readrows():
            print(line)
    print('Tests successful!')

    # Corrupt GZ file test
    reader = ZeekMultiLogReader('../data/http.log.corrupt.gz')
    for line in reader.readrows():
        print(line)


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
