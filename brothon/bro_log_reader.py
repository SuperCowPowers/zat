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
import datetime

# Local Imports
from brothon.utils import file_tailer, file_utils


class BroLogReader(file_tailer.FileTailer):
    """BroLogReader: This class reads in various Bro IDS logs. The class inherits from
                     the FileTailer class so it supports the following use cases:
                       - Read contents of a Bro log file        (tail=False)
                       - Read contents + 'tail -f' Bro log file (tail=True)
           Args:
                filepath (str): The full path the file (/full/path/to/the/file.txt)
                delimiter (str): The delimiter in the Bro IDS logs (default='\t')
                tail (bool): Do a dynamic tail on the file (i.e. tail -f) (default=False)
    """

    def __init__(self, filepath, delimiter='\t', tail=False):
        """Initialization for the BroLogReader Class"""
        self._filepath = filepath
        self._delimiter = delimiter
        self._tail = tail

        # Initialize the Parent Class
        self._parent_class = super(BroLogReader, self)
        self._parent_class.__init__(filepath, full_read=True, tail=self._tail)

    def readrows(self):
        ''' The readrows method reads in the header of the Bro log and
            then uses the parent class to yield each row of the log file
            as a dictionary of {key:value, ...} based on Bro header.
        '''
        # Read in the Bro Headers
        offset, field_names, _ = self._parse_bro_header(self._filepath)

        # Use parent class to yield each row as a dictionary
        for line in self._parent_class.readlines(offset=offset):
            # Check for #close
            if line.startswith('#close'):
                raise StopIteration

            # Yield the line as a dict
            yield self._cast_dict(dict(zip(field_names, line.strip().split(self._delimiter))))

    def _parse_bro_header(self, bro_log):
        """Parse the Bro log header section.
           TODO: Review parsing logic

            Format example:
                #separator \x09
                #set_separator	,
                #empty_field	(empty)
                #unset_field	-
                #path	httpheader_recon
                #fields	ts	origin	useragent	header_events_json
                #types	time	string	string	string
        """

        # Open the Bro logfile
        with open(bro_log, 'r') as bro_file:

            # Skip until you find the #fields line
            _line = bro_file.readline()
            while not _line.startswith('#fields'):
                _line = bro_file.readline()

            # Read in the field names
            field_names = _line.strip().split(self._delimiter)[1:]

            # Read in the types
            _line = bro_file.readline()
            field_types = _line.strip().split(self._delimiter)[1:]

            # Keep the header offset
            offset = bro_file.tell()

        # Return the header info
        return offset, field_names, field_types

    def _cast_dict(self, data_dict):
        ''' Internal method that makes sure any dictionary elements
            are properly cast into the correct types, instead of
            just treating everything like a string from the csv file
        '''
        for key, value in data_dict.items():
            # Check for timestamp
            if key == 'ts':
                data_dict[key] = datetime.datetime.fromtimestamp(float(value))
            else:
                data_dict[key] = self._cast_value(value)
        return data_dict

    @staticmethod
    def _cast_value(value):
        """Try to cast value into a primative type"""
        test_types = (int, float, str)
        for cast_test in test_types:
            try:
                return cast_test(value)
            except ValueError:
                continue
        return value


def test():
    """Test for BroLogReader Python Class"""

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')

    # For each file, create the Class and test the reader
    files = ['conn.log', 'dns.log', 'http.log', 'dhcp.log', 'files.log', 'weird.log']
    for bro_log in files:
        test_path = os.path.join(data_path, bro_log)
        print('Opening Data File: {:s}'.format(test_path))
        reader = BroLogReader(test_path, tail=False)  # First with no tailing
        for line in reader.readrows():
            print(line)
    print('Read with NoTail Test successful!')

    # Now include tailing (note: as an automated test this needs to timeout quickly)
    try:
        from interruptingcow import timeout

        # Spin up the class
        tailer = BroLogReader(test_path, tail=True)

        # Tail the file for 2 seconds and then quit
        try:
            with timeout(2, exception=RuntimeError):
                for line in tailer.readrows():
                    print(line)
        except RuntimeError:  # InterruptingCow raises a RuntimeError on timeout
            print('Tailing Test successful!')

    except ImportError:
        print('Tailing Test not run, need interruptcow module...')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
