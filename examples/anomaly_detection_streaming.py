"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse
import time
import math
from collections import Counter

# Third Party Imports
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans

# Local imports
from bat import bro_log_reader, live_simulator
from bat import dataframe_to_matrix, dataframe_cache


if __name__ == '__main__':
    # Example to show the dataframe cache functionality on streaming data
    pd.set_option('display.width', 200)

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


        # Sanity check for either http or dns log
        if 'http' in args.bro_log:
            log_type = 'http'
            features = ['id.resp_p', 'method', 'resp_mime_types', 'request_body_len']
        elif 'dns' in args.bro_log:
            log_type = 'dns'
            features = ['Z', 'rejected', 'proto', 'query', 'qclass_name', 'qtype_name', 'rcode_name', 'query_length']
        else:
            print('This example only works with Bro with http.log or dns.log files..')
            sys.exit(1)

        # Create a Bro log reader
        print('Opening Data File: {:s}'.format(args.bro_log))
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)

        # OR you could create a live simulator to test it out on a static log file
        # reader = live_simulator.LiveSimulator(args.bro_log)

        # Create a Dataframe Cache
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=600)  # 10 minute cache

        # Add each new row into the cache
        time_delta = 30
        timer = time.time() + time_delta
        for row in reader.readrows():
            df_cache.add_row(row)

            # Every 30 seconds grab the dataframe from the cache
            if time.time() > timer:
                timer = time.time() + time_delta

                # Get the windowed dataframe (10 minute window)
                bro_df = df_cache.dataframe()

                # Add query length
                bro_df['query_length'] = bro_df['query'].str.len()

                # Use the bat DataframeToMatrix class
                features = ['Z', 'rejected', 'proto', 'query', 'qclass_name', 'qtype_name', 'rcode_name', 'query_length', 'id.resp_p']
                to_matrix = dataframe_to_matrix.DataFrameToMatrix()
                bro_matrix = to_matrix.fit_transform(bro_df[features])
                print(bro_matrix.shape)

                # Print out the range of the daterange and some stats
                print('DataFrame TimeRange: {:s} --> {:s}'.format(str(bro_df['ts'].min()), str(bro_df['ts'].max())))

                # Train/fit and Predict anomalous instances using the Isolation Forest model
                odd_clf = IsolationForest(contamination=0.01) # Marking 1% as odd
                odd_clf.fit(bro_matrix)

                # Now we create a new dataframe using the prediction from our classifier
                odd_df = bro_df[odd_clf.predict(bro_matrix) == -1]

                # Now we're going to explore our odd observations with help from KMeans
                num_clusters = min(len(odd_df), 10) # 10 clusters unless we have less than 10 observations
                odd_matrix = to_matrix.fit_transform(odd_df[features])
                odd_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
                print(odd_matrix.shape)

                # Now group the dataframe by cluster
                cluster_groups = odd_df.groupby('cluster')

                # Now print out the details for each cluster
                show_fields = ['id.orig_h', 'id.resp_h'] + features
                print('<<< Outliers Detected! >>>')
                for key, group in cluster_groups:
                    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                    print(group[show_fields].head())



