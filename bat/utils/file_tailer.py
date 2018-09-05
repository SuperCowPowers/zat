"""FileTailer Python Class"""
from __future__ import print_function
import os
import time

# Local imports
from bat.utils import file_utils


class FileTailer(object):
    """FileTailer: Will provide 'tail -f' functionality for a file. The readlines() method
                   returns a generator that yields lines as they are added to the file

        Args:
            filepath (str): The full path the file (/full/path/to/the/file.txt)
            sleep (int): The wait interval in milliseconds (default=50)
            full_read (bool): Read the full file  (default=True)
            tail (bool): Do a dynamic tail on the file (i.e. tail -f) (default=True)
    """
    def __init__(self, filepath, sleep=50, full_read=True, tail=True):
        """FileTailer Initialization"""
        self._filepath = filepath
        self._sleep = sleep * 1e-3
        self._full_read = full_read
        self._tail = tail

    def readlines(self, offset=0):
        """Open the file for reading and yield lines as they are added"""
        try:
            with open(self._filepath) as fp:
                # For full read go through existing lines in file
                if self._full_read:
                    fp.seek(offset)
                    for row in fp:
                        yield row

                # Okay now dynamically tail the file
                if self._tail:
                    while True:
                        current = fp.tell()
                        row = fp.readline()
                        if row:
                            yield row
                        else:
                            fp.seek(current)
                            time.sleep(self._sleep)

        except IOError as err:
            print('Error reading the file {0}: {1}'.format(self._filepath, err))
            return


def test():
    """Test for FileTailer Python Class"""

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../../data')
    test_path = os.path.join(data_path, 'http.log')
    print('Opening Data File: {:s}'.format(test_path))

    # Create the Class
    tailer = FileTailer(test_path, tail=False)  # First with no tailing
    for line in tailer.readlines():
        print(line)
    print('Read with NoTail Test successful!')

    # Now include tailing (note: as an automated test this needs to timeout quickly)
    try:
        from interruptingcow import timeout

        # Spin up the class
        tailer = FileTailer(test_path)  # Tail = True

        # Tail the file for 2 seconds and then quit
        try:
            with timeout(2, exception=RuntimeError):
                for line in tailer.readlines():
                    print(line)
        except RuntimeError:  # InterruptingCow raises a RuntimeError on timeout
            print('Tailing Test successful!')

    except ImportError:
        print('Tailing Test not run, need interruptcow module...')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
