"""Bro IDS log to Pandas Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse

# Local imports
from bat.log_to_dataframe import LogToDataFrame
from bat.dataframe_to_parquet import df_to_parquet

if __name__ == '__main__':
    # Example to populate a Pandas dataframe from a bro log reader

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--bro-log', type=str, help='Specify a bro log to run BroLogReader test on')
    parser.add_argument('-o', '--parquet-file', type=str, help='Specify the parquet file to write to')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # If no args just call help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log and args.parquet_file:
        args.bro_log = os.path.expanduser(args.bro_log)
        args.parquet_file = os.path.expanduser(args.parquet_file)

        # Create a Pandas dataframe from a Bro log
        bro_df = LogToDataFrame(args.bro_log)

        # Print out number of rows
        print('Log has {:d} rows'.format(len(bro_df)))

        # Write out the parquet file
        print('Writing Parquet file: {:s}'.format(args.parquet_file))
        df_to_parquet(bro_df, args.parquet_file)
