"""Bro log to Parquet Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse

# Local imports
from bat.log_to_parquet import log_to_parquet

if __name__ == '__main__':
    # Example to write Parquet file from a bro log

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('bro_log', type=str, help='Specify a bro log to run BroLogReader test on')
    parser.add_argument('-o', '--parquet-file', type=str, required=True, help='Specify the parquet file to write to')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log and args.parquet_file:
        args.bro_log = os.path.expanduser(args.bro_log)
        args.parquet_file = os.path.expanduser(args.parquet_file)

        # Write out the parquet file
        print('Writing Parquet file: {:s}'.format(args.parquet_file))
        log_to_parquet(args.bro_log, args.parquet_file)
