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


def df_to_parquet(df, filename, compression='SNAPPY'):
    """write_to_parquet: Converts a Pandas DataFrame into a Parquet file
        Args:
            df (pandas dataframe): The Pandas Dataframe to be saved as parquet file
            filename (string): The full path to the filename for the Parquet file
    """

    # Right now there are two open Parquet issues
    # Timestamps in Spark: https://issues.apache.org/jira/browse/ARROW-1499
    # TimeDelta Support: https://issues.apache.org/jira/browse/ARROW-835
    for column in df.columns:
        if(df[column].dtype == 'timedelta64[ns]'):
            print('Converting timedelta column {:s}...'.format(column))
            df[column] = df[column].astype(str)

    arrow_table = pa.Table.from_pandas(df)
    if compression == 'UNCOMPRESSED':
        compression = None
    pq.write_table(arrow_table, filename, compression=compression, use_deprecated_int96_timestamps=True)


def parquet_to_df(filename, nthreads=1):
    """parquet_to_df: Reads a Parquet file into a Pandas DataFrame
        Args:
            filename (string): The full path to the filename for the Parquet file
            ntreads (int): The number of threads to use (defaults to 1)
    """
    try:
        return pq.read_table(filename, nthreads=nthreads).to_pandas()
    except pa.lib.ArrowIOError:
        print('Could not read parquet file {:s}'.format(filename))
        return None


# Simple test of the functionality
def test():
    """Test for methods in this file"""
    import os
    pd.set_option('display.width', 1000)
    from bat.dataframe_to_parquet import df_to_parquet, parquet_to_df
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
    df_to_parquet(dns_df, filename)

    # Read from the parquet file
    new_dns_df = parquet_to_df(filename)

    # Remove temp file
    os.remove(filename)

    # Print out the head
    print(new_dns_df.head())

    # Make sure our conversions didn't lose type info
    assert(dns_df.dtypes.values.tolist() == new_dns_df.dtypes.values.tolist())

    print('DataFrame to Parquet Tests successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
