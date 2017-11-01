"""DataFrameToParquet: Converts a Pandas DataFrame into a Parquet file
   Note:
        Big Thanks to Wes McKinney. This code was borrowed/stolen from
        this article: http://wesmckinney.com/blog/python-parquet-update
"""
from __future__ import print_function

# Third Party
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Local Imports
from bat.bro_log_reader import BroLogReader


def _make_df(rows):
    """Internal Method to make and clean the dataframe in preparation for sending to Parquet"""

    # Make DataFrame
    df = pd.DataFrame(rows).set_index('ts')

    # TimeDelta Support: https://issues.apache.org/jira/browse/ARROW-835
    for column in df.columns:
        if(df[column].dtype == 'timedelta64[ns]'):
            print('Converting timedelta column {:s}...'.format(column))
            df[column] = df[column].astype(str)
    return df


def log_to_parquet(bro_log, parquet_file, compression='SNAPPY', row_group_size=1000000):
    """write_to_parquet: Converts a Bro log into a Parquet file
        Args:
            bro_log (string: The full path to the bro log to be saved as a Parquet file
            parquet_file (string): The full path to the filename for the Parquet file
            compression (string): The compression algo to use (defaults to 'SNAPPY')
            row_group_size (int): The size of the parquet row groups (defaults to 1000000)
        Notes:
            Right now there are two open Parquet issues
            - Timestamps in Spark: https://issues.apache.org/jira/browse/ARROW-1499
            - TimeDelta Support: https://issues.apache.org/jira/browse/ARROW-835
    """

    # Set up various parameters
    current_row_set = []
    writer = None
    num_rows = 0

    # Spin up the bro reader on a given log file
    reader = BroLogReader(bro_log)
    for num_rows, row in enumerate(reader.readrows()):

        # Append the row to the row set
        current_row_set.append(row)

        # If we have enough rows add to the Parquet table
        if num_rows % row_group_size == 0:
            print('Writing {:d} rows...'.format(num_rows))
            if writer is None:
                arrow_table = pa.Table.from_pandas(_make_df(current_row_set))
                writer = pq.ParquetWriter(parquet_file, arrow_table.schema, compression=compression, use_deprecated_int96_timestamps=True)
                writer.write_table(arrow_table)
            else:
                arrow_table = pa.Table.from_pandas(_make_df(current_row_set))
                writer.write_table(arrow_table)

            # Empty the current row set
            current_row_set = []

    # Add any left over rows and close the Parquet file
    if num_rows:
        print('Writing {:d} rows...'.format(num_rows))
        arrow_table = pa.Table.from_pandas(_make_df(current_row_set))
        writer.write_table(arrow_table)
        writer.close()
        print('Parquet File Complete')


# Simple test of the functionality
def test():
    """Test for methods in this file"""
    import os
    pd.set_option('display.width', 1000)
    from bat.dataframe_to_parquet import parquet_to_df
    from bat.log_to_dataframe import LogToDataFrame
    from bat.utils import file_utils
    import tempfile

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    test_path = os.path.join(data_path, 'dns.log')

    # Convert the log to a Pandas DataFrame
    dns_df = LogToDataFrame(test_path)

    # Print out the head
    print(dns_df.head())

    # Create a temporary file
    filename = tempfile.NamedTemporaryFile(delete=False).name

    # Write to a parquet file
    log_to_parquet(test_path, filename)

    # Read from the parquet file
    new_dns_df = parquet_to_df(filename)

    # Remove temp file
    os.remove(filename)

    # Print out the head
    print(new_dns_df.head())

    # Make sure our conversions didn't lose type info
    # TODO: Uncomment this test when the following PR is fixed
    #       - TimeDelta Support: https://issues.apache.org/jira/browse/ARROW-835
    # assert(dns_df.dtypes.values.tolist() == new_dns_df.dtypes.values.tolist())

    # Test an empty log (a log with header/close but no data rows)
    test_path = os.path.join(data_path, 'http_empty.log')
    filename = tempfile.NamedTemporaryFile(delete=False).name
    log_to_parquet(test_path, filename)
    parquet_to_df(filename)
    os.remove(filename)

    print('DataFrame to Parquet Tests successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
