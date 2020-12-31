"""Zeek log to Parquet Dataframe Example"""
import os
import sys
import argparse

# Local imports
from zat.log_to_dataframe import LogToDataFrame


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
        zeek_df.to_parquet(args.parquet_file, compression='gzip')  # Snappy is better, but often not installed
        print('Complete: {:s} --> {:s}'.format(args.zeek_log, args.parquet_file))
