"""Zeek log to Pandas Dataframe + Filter by WhiteList Example"""

import os
import sys
import argparse
import pandas as pd

# Local imports
from zat.log_to_dataframe import LogToDataFrame

if __name__ == '__main__':
    # Example to populate a Pandas dataframe from a zeek log reader

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('dns_log', help='Specify the zeek DNS log')
    parser.add_argument('whitelist', help='Specify the DNS whiteliist')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Grab the whitelist
    white_df = pd.read_csv(args.whitelist, names=['rank', 'domain'])
    whitelist = white_df['domain'].tolist()

    # File may have a tilde in it
    if args.dns_log:
        args.dns_log = os.path.expanduser(args.dns_log)

        # Create a Pandas dataframe from a Zeek log
        log_to_df = LogToDataFrame()
        zeek_df = log_to_df.create_dataframe(args.dns_log)

        # Print out the head of the dataframe
        print('DF Size before whitelist: {:d} rows'.format(len(zeek_df)))

        # Filter the dataframe with the whitelist
        white_df = zeek_df[zeek_df['query'].isin(whitelist)]
        print('Filtering out {!r}'.format(white_df['query'].tolist()))
        zeek_df = zeek_df[~zeek_df['query'].isin(whitelist)]

        print('DF Size after whitelist: {:d} rows'.format(len(zeek_df)))
