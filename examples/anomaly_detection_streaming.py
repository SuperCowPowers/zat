"""FileTailer Python Class"""

import argparse
import math
import os
import sys
import time
from collections import Counter

# Third Party Imports
import pandas as pd
from sklearn.cluster import MiniBatchKMeans
from sklearn.ensemble import IsolationForest

try:
    import hdbscan
except ImportError:
    print("This example needs hdbscan '$ pip install hdbscan'")
    sys.exit(1)

# Local imports
from zat import dataframe_cache, dataframe_to_matrix, live_simulator


def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


if __name__ == "__main__":
    # Example to show the dataframe cache functionality on streaming data
    pd.set_option("display.width", 200)

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument("zeek_log", type=str, help="Specify a zeek log to run ZeekLogReader test on")
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print("Unrecognized args: %s" % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Sanity check dns log
        if "dns" in args.zeek_log:
            log_type = "dns"
        else:
            print("This example only works with Zeek with dns.log files..")
            sys.exit(1)

        # Create a Zeek IDS log live simulator
        print("Opening Data File: {:s}".format(args.zeek_log))
        reader = live_simulator.LiveSimulator(args.zeek_log, eps=10)  # 10 events per second

        # Create a Dataframe Cache
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=600)  # 10 minute cache

        # Streaming Clustering Class
        batch_kmeans = MiniBatchKMeans(n_clusters=5, verbose=True)

        # Density based clustering for each outlier window
        hdbscan_clusterer = hdbscan.HDBSCAN(min_cluster_size=5, min_samples=2)

        # Use the ZeekThon DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()

        # Add each new row into the cache
        time_delta = 10
        timer = time.time() + time_delta
        FIRST_TIME = True
        for row in reader.rows():
            df_cache.add_row(row)

            # Every 30 seconds grab the dataframe from the cache
            if time.time() > timer:
                timer = time.time() + time_delta

                # Get the windowed dataframe (10 minute window)
                zeek_df = df_cache.dataframe()

                # Compute some addition data
                zeek_df["query_length"] = zeek_df["query"].str.len()
                zeek_df["answer_length"] = zeek_df["answers"].str.len()
                zeek_df["entropy"] = zeek_df["query"].map(lambda x: entropy(x))

                # Use the zat DataframeToMatrix class
                features = ["Z", "proto", "qtype_name", "query_length", "answer_length", "entropy", "id.resp_p"]
                to_matrix = dataframe_to_matrix.DataFrameToMatrix()
                zeek_matrix = to_matrix.fit_transform(zeek_df[features])
                print(zeek_matrix.shape)

                # Print out the range of the daterange and some stats
                print("DataFrame TimeRange: {:s} --> {:s}".format(str(zeek_df["ts"].min()), str(zeek_df["ts"].max())))

                # Train/fit and Predict anomalous instances using the Isolation Forest model
                odd_clf = IsolationForest(contamination=0.2)  # Marking 20% as odd
                predictions = odd_clf.fit_predict(zeek_matrix)
                odd_df = zeek_df[predictions == -1].copy()
                if odd_df.empty:
                    print("No outliers detected in this window")
                    continue

                # Now we're going to explore our odd observations with help from KMeans
                odd_matrix = to_matrix.transform(odd_df[features])
                batch_kmeans.partial_fit(odd_matrix)
                clusters = batch_kmeans.predict(odd_matrix).tolist()
                odd_df["kmeans_cluster"] = clusters

                # HDBSCAN gives us a density based view of the same outlier window.
                # Cluster value -1 means HDBSCAN considers that observation noise.
                if len(odd_df) >= hdbscan_clusterer.min_cluster_size:
                    odd_df["hdbscan_cluster"] = hdbscan_clusterer.fit_predict(odd_matrix)
                else:
                    odd_df["hdbscan_cluster"] = -1

                # Now group the dataframe by cluster
                cluster_groups = odd_df.groupby("kmeans_cluster")

                # Now print out the details for each cluster
                show_fields = ["id.orig_h", "id.resp_h", "query"] + features + ["hdbscan_cluster"]
                print("<<< Outliers Detected: MiniBatchKMeans clusters >>>")
                for key, group in cluster_groups:
                    print("\nCluster {:d}: {:d} observations".format(key, len(group)))
                    print(group[show_fields].head())

                hdbscan_groups = odd_df.groupby("hdbscan_cluster")
                print("<<< Outliers Detected: HDBSCAN clusters >>>")
                for key, group in hdbscan_groups:
                    print("\nCluster {:d}: {:d} observations".format(key, len(group)))
                    print(group[show_fields].head())
