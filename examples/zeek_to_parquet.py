"""Zeek log to Parquet Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse
from pyspark.sql import SparkSession

# Local imports
from zat import log_to_sparkdf


# Helper method
def log_to_parquet(log_in, parquet_out):
    # Spin up a local Spark Session (with 4 executors)
    spark = SparkSession.builder.master('local[4]').appName('my_awesome').getOrCreate()

    # Use the ZAT class to load our log file into a Spark dataframe (2 lines of code!)
    spark_it = log_to_sparkdf.LogToSparkDF(spark)
    spark_df = spark_it.create_dataframe(log_in)

    # Write it out as a parquet file
    spark_df.write.parquet(parquet_out)
    print('{:s} --> {:s}'.format(log_in, parquet_out))


if __name__ == '__main__':
    # Example to write Parquet file from a bro log

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify the zeek log input file')
    parser.add_argument('parquet_file', type=str, help='Specify the parquet file to write out')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log and args.parquet_file:
        args.zeek_log = os.path.expanduser(args.zeek_log)
        args.parquet_file = os.path.expanduser(args.parquet_file)

        # Write out the parquet file
        log_to_parquet(args.zeek_log, args.parquet_file)
