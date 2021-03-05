"""Zeek log to Parquet Dataframe Example"""
import os
import sys
import argparse

# Note: We're going to import pyarrow but it currently has an open issue around supporting time deltas
#    - https://issues.apache.org/jira/browse/ARROW-6780 so we have to convert timedelta fields to str
# Also see:
#   - https://stackoverflow.com/questions/53893554/transfer-and-write-parquet-with-python-and-pandas-got-timestamp-error
#
from datetime import timedelta
import pandas as pd
try:
    import pyarrow
except ImportError:
    print('Please > pip install pyarrow')
    sys.exit(1)

# Local imports
from zat.log_to_dataframe import LogToDataFrame


# Helper method for temporarily converting timedelta to string
def convert_timedelta_to_str(df):
    delta_columns = df.select_dtypes(include=['timedelta'])
    for column in delta_columns:
        df[column] = df[column].apply(tdelta_value_to_str)
    return df


def tdelta_value_to_str(value):
    if pd.isnull(value):
        return '-'  # Standard for Zeek null value
    else:
        return str(timedelta(seconds=value.total_seconds()))


if __name__ == '__main__':
    # Example to write Parquet file from a zeek log

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify the zeek log input file')
    parser.add_argument('parquet_file', type=str, help='Specify the parquet file to write out')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log and args.parquet_file:
        args.zeek_log = os.path.expanduser(args.zeek_log)
        args.parquet_file = os.path.expanduser(args.parquet_file)

        # Convert to dataframe and write out the parquet file
        log_to_df = LogToDataFrame()
        zeek_df = log_to_df.create_dataframe(args.zeek_log)
        print('Dataframe Created: {:d} rows...'.format(len(zeek_df)))

        # Check for any timedelta fields (see note above)
        df = convert_timedelta_to_str(zeek_df)

        zeek_df.to_parquet(args.parquet_file, compression='snappy', use_deprecated_int96_timestamps=True)
        print('Complete: {:s} --> {:s}'.format(args.zeek_log, args.parquet_file))
