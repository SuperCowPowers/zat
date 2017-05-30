# Example that demonstrates going from Bro IDS data to scikit-learn models
from __future__ import print_function
import os
import sys
import argparse

# Third Party Imports
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import numpy as np

# Local imports
from brothon import bro_log_reader
from brothon.analysis import dataframe_to_matrix

# Helper method for scatter/beeswarm plot
def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev

if __name__ == '__main__':
    # Example that demonstrates going from Bro IDS data to scikit-learn models

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

    # Sanity check that this is a dns log
    if not args.bro_log.endswith('dns.log'):
        print('This example only works with Bro dns.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Create a bro reader on a given log file
        reader = bro_log_reader.BroLogReader(args.bro_log)

        # Create a Pandas dataframe from reader
        bro_df = pd.DataFrame(reader.readrows())

        # Add query length
        bro_df['query_length'] = bro_df['query'].str.len()

        # Normalize this field
        ql = bro_df['query_length']
        bro_df['query_length_norm'] = (ql - ql.min()) / (ql.max()-ql.min())

        # These are the features we want (note some of these are categorical!)
        features = ['AA', 'RA', 'RD', 'TC', 'Z', 'rejected', 'proto', 'query',
                    'qclass_name', 'qtype_name', 'rcode_name', 'query_length_norm']
        feature_df = bro_df[features]

        # Use the super awesome DataframeToMatrix class (handles categorical data!)
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        bro_matrix = to_matrix.fit_transform(feature_df)

        # Now we're ready for scikit-learn!
        # Just some simple stuff for this example, KMeans and PCA
        kmeans = KMeans(n_clusters=5).fit_predict(bro_matrix)
        pca = PCA(n_components=2).fit_transform(bro_matrix)

        # Now we can put our ML results back onto our dataframe!
        bro_df['x'] = jitter(pca[:, 0]) # PCA X Column
        bro_df['y'] = jitter(pca[:, 1]) # PCA Y Column
        bro_df['cluster'] = kmeans

        # Now use dataframe group by cluster
        show_fields = ['query', 'Z', 'proto', 'qtype_name', 'x', 'y', 'cluster']
        cluster_groups = bro_df[show_fields].groupby('cluster')

        # Plot the Machine Learning results
        fig, ax = plt.subplots()
        colors = {0:'green', 1:'blue', 2:'red', 3:'orange', 4:'purple'}
        for key, group in cluster_groups:
            group.plot(ax=ax, kind='scatter', x='x', y='y', alpha=0.6, s=60,
                       label='Cluster: {:d}'.format(key), color=colors[key])
        plt.show()

        # Now print out the details for each cluster
        for key, group in cluster_groups:
            print('Rows in Cluster: {:d}'.format(len(group)))
            print(group.head(), '\n')
