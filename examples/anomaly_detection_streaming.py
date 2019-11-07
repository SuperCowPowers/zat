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
from sklearn.cluster import MiniBatchKMeans

# Local imports
from zat import bro_log_reader, live_simulator
from zat import dataframe_to_matrix, dataframe_cache


def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


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

        # Sanity check dns log
        if 'dns' in args.bro_log:
            log_type = 'dns'
        else:
            print('This example only works with Zeek with dns.log files..')
            sys.exit(1)

        # Create a Zeek log reader
        print('Opening Data File: {:s}'.format(args.bro_log))
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)

        # Create a Zeek IDS log live simulator
        print('Opening Data File: {:s}'.format(args.bro_log))
        reader = live_simulator.LiveSimulator(args.bro_log, eps=10)  # 10 events per second

        # Create a Dataframe Cache
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=600)  # 10 minute cache

        # Streaming Clustering Class
        batch_kmeans = MiniBatchKMeans(n_clusters=5, verbose=True)

        # Use the BroThon DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()

        # Add each new row into the cache
        time_delta = 10
        timer = time.time() + time_delta
        FIRST_TIME = True
        for row in reader.readrows():
            df_cache.add_row(row)

            # Every 30 seconds grab the dataframe from the cache
            if time.time() > timer:
                timer = time.time() + time_delta

                # Get the windowed dataframe (10 minute window)
                bro_df = df_cache.dataframe()

                # Compute some addition data
                bro_df['query_length'] = bro_df['query'].str.len()
                bro_df['answer_length'] = bro_df['answers'].str.len()
                bro_df['entropy'] = bro_df['query'].map(lambda x: entropy(x))

                # Use the zat DataframeToMatrix class
                features = ['Z', 'proto', 'qtype_name', 'query_length', 'answer_length', 'entropy', 'id.resp_p']
                to_matrix = dataframe_to_matrix.DataFrameToMatrix()
                bro_matrix = to_matrix.fit_transform(bro_df[features])
                print(bro_matrix.shape)

                # Print out the range of the daterange and some stats
                print('DataFrame TimeRange: {:s} --> {:s}'.format(str(bro_df['ts'].min()), str(bro_df['ts'].max())))

                # Train/fit and Predict anomalous instances using the Isolation Forest model
                odd_clf = IsolationForest(contamination=0.2)  # Marking 20% as odd
                predictions = odd_clf.fit_predict(bro_matrix)
                odd_df = bro_df[predictions == -1]

                # Now we're going to explore our odd observations with help from KMeans
                odd_matrix = to_matrix.transform(odd_df[features])
                batch_kmeans.partial_fit(odd_matrix)
                clusters = batch_kmeans.predict(odd_matrix).tolist()
                odd_df['cluster'] = clusters

                # Now group the dataframe by cluster
                cluster_groups = odd_df.groupby('cluster')

                # Now print out the details for each cluster
                show_fields = ['id.orig_h', 'id.resp_h', 'query'] + features
                print('<<< Outliers Detected! >>>')
                for key, group in cluster_groups:
                    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                    print(group[show_fields].head())
