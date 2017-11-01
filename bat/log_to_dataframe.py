"""LogToDataFrame: Converts a Bro log to a Pandas DataFrame"""
from __future__ import print_function

# Third Party
import pandas as pd

# Local Imports
from bat import bro_log_reader


class LogToDataFrame(pd.DataFrame):
    """LogToDataFrame: Converts a Bro log to a Pandas DataFrame
        Args:
            log_fllename (string): The full path to the Bro log
            ts_index (bool): Set the index to the 'ts' field (default = True)
        Notes:
            This class is fairly simple right now but will probably have additional
            functionality for formal type specifications and performance enhancements
    """
    def __init__(self, log_filename, ts_index=True):
        """Initialize the LogToDataFrame class"""

        # Create a bro reader on a given log file
        reader = bro_log_reader.BroLogReader(log_filename)

        # Create a Pandas dataframe from reader
        super(LogToDataFrame, self).__init__(reader.readrows())

        # Set the index
        if ts_index and not self.empty:
            self.set_index('ts', inplace=True)


# Simple test of the functionality
def test():
    """Test for LogToDataFrame Class"""
    import os
    pd.set_option('display.width', 1000)
    from bat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    test_path = os.path.join(data_path, 'http.log')

    # Convert it to a Pandas DataFrame
    http_df = LogToDataFrame(test_path)

    # Print out the head
    print(http_df.head())

    # Print out the datatypes
    print(http_df.dtypes)

    # Test an empty log (a log with header/close but no data rows)
    test_path = os.path.join(data_path, 'http_empty.log')
    http_df = LogToDataFrame(test_path)

    # Print out the head
    print(http_df.head())

    # Print out the datatypes
    print(http_df.dtypes)

    print('LogToDataFrame Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
