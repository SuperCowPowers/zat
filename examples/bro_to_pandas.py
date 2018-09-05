"""Bro log to Pandas Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse

# Local imports
from bat.log_to_dataframe import LogToDataFrame

if __name__ == '__main__':
    # Example to populate a Pandas dataframe from a bro log reader

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('bro_log', type=str, help='Specify a bro log to run BroLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Create a Pandas dataframe from a Bro log
        bro_df = LogToDataFrame(args.bro_log)

        # Print out the head of the dataframe
        print(bro_df.head())

        # Print out the types of the columns
        print(bro_df.dtypes)
