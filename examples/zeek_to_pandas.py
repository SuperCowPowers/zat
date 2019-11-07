"""Zeek log to Pandas Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse

# Local imports
from zat.log_to_dataframe import LogToDataFrame

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

        # Create a Pandas dataframe from a Zeek log
        log_to_df = LogToDataFrame()
        bro_df = log_to_df.create_dataframe(args.bro_log)

        # Print out the head of the dataframe
        print(bro_df.head())

        # Print out the types of the columns
        print(bro_df.dtypes)

        # Print out size and memory usage
        print('DF Shape: {:s}'.format(str(bro_df.shape)))
        print('DF Memory:')
        memory_usage = bro_df.memory_usage(deep=True)
        total = memory_usage.sum()
        for item in memory_usage.items():
            print('\t {:s}: \t{:.2f} MB'.format(item[0], item[1]/1e6))
        print('DF Total: {:.2f} GB'.format(total/(1e9)))
