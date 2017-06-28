"""Anomaly Detection Example"""
from __future__ import print_function
import os
import sys
import argparse

# Third Party Imports
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans

# Local imports
from brothon import bro_log_reader
from brothon.analysis import dataframe_to_matrix


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

        # Sanity check either http or dns log
        if 'http' in args.bro_log:
            log_type = 'http'
            features = ['id.resp_p', 'method', 'resp_mime_types', 'request_body_len']
        elif 'dns' in args.bro_log:
            log_type = 'dns'
            features = ['Z', 'rejected', 'proto', 'query', 'qclass_name', 'qtype_name', 'rcode_name', 'query_length']
        else:
            print('This example only works with Bro with http.log or dns.log files..')
            sys.exit(1)

        # Create a Bro IDS log reader
        print('Opening Data File: {:s}'.format(args.bro_log))
        reader = bro_log_reader.BroLogReader(args.bro_log)

        # Create a Pandas dataframe from reader
        bro_df = pd.DataFrame(reader.readrows())
        print('Read in {:d} Rows...'.format(len(bro_df)))

        # Using Pandas we can easily and efficiently compute additional data metrics
        # Here we use the vectorized operations of Pandas/Numpy to compute query length
        if log_type == 'dns':
            bro_df['query_length'] = bro_df['query'].str.len()

        # Use the BroThon DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        bro_matrix = to_matrix.fit_transform(bro_df[features])
        print(bro_matrix.shape)

        # Train/fit and Predict anomalous instances using the Isolation Forest model
        odd_clf = IsolationForest(contamination=0.2) # Marking 20% as odd
        odd_clf.fit(bro_matrix)

        # Now we create a new dataframe using the prediction from our classifier
        odd_df = bro_df[features][odd_clf.predict(bro_matrix) == -1]

        # Now we're going to explore our odd observations with help from KMeans
        odd_matrix = to_matrix.fit_transform(odd_df)
        num_clusters = min(len(odd_df), 4) # 4 clusters unless we have less than 4 observations
        odd_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
        print(odd_matrix.shape)

        # Now group the dataframe by cluster
        cluster_groups = odd_df[features+['cluster']].groupby('cluster')

        # Now print out the details for each cluster
        print('<<< Outliers Detected! >>>')
        for key, group in cluster_groups:
            print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
            print(group.head())

