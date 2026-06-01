"""FileTailer Python Class"""

import os
import time

# Local imports
from zat.utils import file_utils


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

    @staticmethod
    def _file_signature(file_info):
        """Return a stable signature for comparing opened files with path stats."""
        return (file_info.st_dev, file_info.st_ino)

    def _was_rotated(self, fp, offset):
        """Return True when the tailed file was replaced or truncated."""
        try:
            current_path = os.stat(self._filepath)
        except OSError:
            return True

        open_file = os.fstat(fp.fileno())
        if self._file_signature(current_path) != self._file_signature(open_file):
            return True

        return offset > current_path.st_size

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
                            if self._was_rotated(fp, current):
                                return
                            fp.seek(current)
                            time.sleep(self._sleep)

        except IOError as err:
            print("Error reading the file {0}: {1}".format(self._filepath, err))
            return


def test():
    """Test for FileTailer Python Class"""

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, "../../data")
    test_path = os.path.join(data_path, "http.log")
    print("Opening Data File: {:s}".format(test_path))

    # Create the Class
    tailer = FileTailer(test_path, tail=False)  # First with no tailing
    for line in tailer.readlines():
        print(line)
    print("Read with NoTail Test successful!")

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
            print("Tailing Test successful!")

    except ImportError:
        print("Tailing Test not run, need interruptcow module...")


def test_detects_copytruncate_rotation(tmp_path):
    """A tailer should stop reading an opened file after copytruncate rotation."""
    test_path = tmp_path / "rotating.log"
    test_path.write_text("first\nsecond\n", encoding="utf-8")
    tailer = FileTailer(str(test_path))

    with open(test_path, "r+") as fp:
        fp.seek(0, os.SEEK_END)
        offset = fp.tell()
        fp.truncate(0)
        fp.flush()

        assert tailer._was_rotated(fp, offset)


def test_unrotated_file_is_not_reported_as_rotated(tmp_path):
    """An unchanged tailed file should not be treated as rotated."""
    test_path = tmp_path / "rotating.log"
    test_path.write_text("first\n", encoding="utf-8")
    tailer = FileTailer(str(test_path))

    with open(test_path) as fp:
        offset = fp.tell()

        assert not tailer._was_rotated(fp, offset)


def test_detects_renamed_recreated_rotation(tmp_path):
    """A tailer should stop reading an opened file after rename/create rotation."""
    import pytest

    if os.name == "nt":
        pytest.skip("Windows cannot rename an open file handle.")

    test_path = tmp_path / "rotating.log"
    test_path.write_text("first\n", encoding="utf-8")
    tailer = FileTailer(str(test_path))

    with open(test_path) as fp:
        offset = fp.tell()
        test_path.rename(tmp_path / "rotating.log.1")
        test_path.write_text("second\n", encoding="utf-8")

        assert tailer._was_rotated(fp, offset)


if __name__ == "__main__":
    # Run the test for easy testing/debugging
    test()
