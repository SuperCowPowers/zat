# Example that demonstrates going from Zeek data to scikit-learn models

import os
import sys
import argparse

# Third Party Imports
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.cluster import KMeans
import numpy as np

# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix

# Helper method for scatter/beeswarm plot
def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev

if __name__ == '__main__':
    # Example that demonstrates going from Zeek data to scikit-learn models

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a dns log
    if 'dns' not in args.zeek_log:
        print('This example only works with Zeek dns.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Create a Pandas dataframe from the Zeek log
        log_to_df = log_to_dataframe.LogToDataFrame()
        zeek_df = log_to_df.create_dataframe(args.zeek_log)

        # Add query length
        zeek_df['query_length'] = zeek_df['query'].str.len()

        # Normalize this field
        #ql = zeek_df['query_length']
        #zeek_df['query_length_norm'] = (ql - ql.min()) / (ql.max()-ql.min())

        # These are the features we want (note some of these are categorical!)
        features = ['AA', 'RA', 'RD', 'TC', 'Z', 'rejected', 'proto', 'qtype_name', 'rcode_name', 'query_length']
        feature_df = zeek_df[features]

        # Use the super awesome DataframeToMatrix class (handles categorical data!)
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        zeek_matrix = to_matrix.fit_transform(feature_df)

        # Now we're ready for scikit-learn!
        # Just some simple stuff for this example, KMeans and PCA
        kmeans = KMeans(n_clusters=5).fit_predict(zeek_matrix)
        pca = PCA(n_components=2).fit_transform(zeek_matrix)

        # Now we can put our ML results back onto our dataframe!
        zeek_df['x'] = jitter(pca[:, 0]) # PCA X Column
        zeek_df['y'] = jitter(pca[:, 1]) # PCA Y Column
        zeek_df['cluster'] = kmeans

        # Now use dataframe group by cluster
        show_fields = ['query', 'Z', 'proto', 'qtype_name', 'x', 'y', 'cluster']
        cluster_groups = zeek_df[show_fields].groupby('cluster')

        # Now print out the details for each cluster
        pd.set_option('display.width', 1000)
        for key, group in cluster_groups:
            print('Rows in Cluster: {:d}'.format(len(group)))
            print(group.head(), '\n')
