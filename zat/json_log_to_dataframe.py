"""JSONLogToDataFrame: Converts a Zeek JSON log to a Pandas DataFrame"""

import os

# Third Party
import pandas as pd

# Local Imports


class JSONLogToDataFrame(object):
    """JSONLogToDataFrame: Converts a Zeek JSON log to a Pandas DataFrame
        Notes:
            Unlike the regular Zeek logs, when you dump the data to JSON you lose
            all the type information. This means we have to guess/infer a lot
            of the types, we HIGHLY recommend that you use the standard Zeek output
            log format as it will result in both faster and better dataframes.
        Todo:
            1. Have a more formal column mapping
            2. Convert Categorial columns
    """
    def __init__(self):
        """Initialize the JSONLogToDataFrame class"""

        # Type conversion Map: This is simple for now but can/should be improved
        self.type_map = {}

    def create_dataframe(self, log_filename, ts_index=True, aggressive_category=True, maxrows=None):
        """ Create a Pandas dataframe from a Zeek JSON log file
            Args:
               log_filename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               maxrows: Read in a subset of rows for testing/inspecting (default = None)
        """
        # Sanity check the filename
        if not os.path.isfile(log_filename):
            print(f'Could not find file: {log_filename}')
            return pd.DataFrame()

        # Read in the JSON file as a dataframe
        _df = pd.read_json(log_filename, nrows=maxrows, lines=True)

        # If we have a ts field convert it to datetime (and optionally set as index)
        if 'ts' in _df.columns:
            _df['ts'] = pd.to_datetime(_df['ts'], unit='s')

            # Set the index
            if ts_index:
                _df.set_index('ts', inplace=True)

        # Okay our dataframe should be ready to go
        return _df


# Simple test of the functionality
def test():
    """Test for JSONLogToDataFrame Class"""
    import os
    pd.set_option('display.width', 1000)
    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data/json')
    log_path = os.path.join(data_path, 'conn.log')

    # Convert it to a Pandas DataFrame
    log_to_df = JSONLogToDataFrame()
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    # Test a bunch
    tests = ['capture_loss.log', 'dhcp.log', 'http.log', 'ntp.log', 'smb_mapping.log', 'weird.log',
             'conn.log', 'dns.log', 'kerberos.log', 'packet_filter.log', 'ssl.log', 'x509.log',
             'dce_rpc.log', 'files.log', 'loaded_scripts.log', 'smb_files.log', 'stats.log']
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print('Testing: {:s}...'.format(log_path))
        my_df = log_to_df.create_dataframe(log_path)
        print(my_df.head())
        print(my_df.dtypes)

    # Test out maxrows arg
    conn_path = os.path.join(data_path, 'conn.log')
    my_df = log_to_df.create_dataframe(conn_path, maxrows=3)
    print(my_df.head())

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, 'http_empty.log')
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print('JSONLogToDataFrame Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging

    # Setup Pandas output options
    pd.options.display.max_colwidth = 20
    pd.options.display.max_columns = 10
    test()
