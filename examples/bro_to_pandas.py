"""Bro IDS log to Pandas Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse

# Third Party Imports
import pandas as pd

# Local imports
from brothon import bro_log_reader

if __name__ == '__main__':
    # Example to populate a Pandas dataframe from a bro log reader

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--bro-log', type=str, help='Specify a bro log to run BroLogReader test on')
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
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Create a bro reader on a given log file
        reader = bro_log_reader.BroLogReader(args.bro_log)

        # Create a Pandas dataframe from reader
        bro_df = pd.DataFrame(reader.readrows())

        # Print out the head of the dataframe
        print(bro_df.head())
