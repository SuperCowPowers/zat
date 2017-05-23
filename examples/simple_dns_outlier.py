"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse
import time
import math
from collections import Counter

# Third Party Imports
try:
    import pandas as pd
except ImportError:
    print('\nThis example needs pandas. Please do a $pip install pandas and rerun this example')
    sys.exit(1)

# Local imports
from brothon import bro_log_reader, live_simulator
from brothon.analysis import dataframe_cache

def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def outliers(df_series):
    # Compute outliers for a series in a DataFrame
    # Note: This is a TOY example, assuming a gaussian distribution which it isn't, etc..
    mean_delta = abs(df_series - df_series.mean())
    return mean_delta > df_series.std() * 2.0  # Greater than 2 std


if __name__ == '__main__':
    # Example to show the dataframe cache functionality on streaming data
    pd.set_option('display.width', 1000)

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

        # Create a Bro IDS log reader
        print('Opening Data File: {:s}'.format(args.bro_log))
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)

        # OR you could create a live simulator to test it out on a static log file
        # reader = live_simulator.LiveSimulator(args.bro_log)

        # Create a Dataframe Cache
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=30)  # 30 second cache

        # Add each new row into the cache
        time_delta = 5
        timer = time.time() + time_delta
        for row in reader.readrows():
            df_cache.add_row(row)

            # Every 5 seconds grab the dataframe from the cache
            if time.time() > timer:
                timer = time.time() + time_delta

                # Get the windowed dataframe (10 second window)
                my_df = df_cache.dataframe()

                # Add query length and entropy
                my_df['query_length'] = my_df['query'].str.len()
                my_df['query_entropy'] = my_df['query'].apply(lambda x: entropy(x))

                # Print out the range of the daterange and some stats
                print('DataFrame TimeRange: {:s} --> {:s}'.format(str(my_df['ts'].min()), str(my_df['ts'].max())))

                # Compute Outliers
                # Note: This is a TOY example, assuming a gaussian distribution which it isn't, etc..
                my_outliers = my_df[outliers(my_df['query_length'])]
                if not my_outliers.empty:
                    print('<<< Outliers Detected! >>>')
                    print(my_outliers[['query','query_length', 'query_entropy']])



