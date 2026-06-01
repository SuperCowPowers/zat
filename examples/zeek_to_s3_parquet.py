"""Write a Zeek log to an S3 Parquet dataset with AWS SDK for pandas."""

import argparse
import os
import sys
from datetime import timedelta

import pandas as pd

from zat.log_to_dataframe import LogToDataFrame


def load_awswrangler():
    """Import AWS SDK for pandas only when this example is executed."""
    try:
        import awswrangler as wr
    except ImportError:
        print("Please > pip install 'zat[aws]' or pip install awswrangler")
        sys.exit(1)
    return wr


def convert_timedelta_to_str(df):
    """Convert timedelta columns to strings before writing Parquet."""
    delta_columns = df.select_dtypes(include=["timedelta"])
    for column in delta_columns:
        df[column] = df[column].apply(tdelta_value_to_str)
    return df


def tdelta_value_to_str(value):
    """Return a Zeek-compatible string for null or timedelta values."""
    if pd.isnull(value):
        return "-"
    return str(timedelta(seconds=value.total_seconds()))


def create_boto3_session(profile_name):
    """Create a boto3 session when a named AWS profile is requested."""
    if not profile_name:
        return None

    try:
        import boto3
    except ImportError:
        print("Please > pip install boto3")
        sys.exit(1)

    return boto3.Session(profile_name=profile_name)


def parse_args():
    """Collect command-line arguments for the S3 Parquet example."""
    parser = argparse.ArgumentParser()
    parser.add_argument("zeek_log", type=str, help="Specify the Zeek log input file")
    parser.add_argument("s3_path", type=str, help="Specify the S3 dataset path, for example s3://bucket/zat/http/")
    parser.add_argument("--database", type=str, help="Optional Glue/Athena database name")
    parser.add_argument("--table", type=str, help="Optional Glue/Athena table name")
    parser.add_argument("--profile-name", type=str, help="Optional AWS profile name")
    parser.add_argument("--partition-cols", nargs="*", help="Optional columns to partition by")
    parser.add_argument(
        "--mode",
        choices=["append", "overwrite", "overwrite_partitions"],
        default="overwrite",
        help="Dataset write mode",
    )
    parser.add_argument("--no-index", action="store_true", help="Do not write the DataFrame index")
    args, commands = parser.parse_known_args()

    if commands:
        print("Unrecognized args: %s" % commands)
        sys.exit(1)

    if bool(args.database) != bool(args.table):
        parser.error("--database and --table must be supplied together")

    return args


if __name__ == "__main__":
    # Example to write a Zeek log as a partitionable S3 Parquet dataset.
    args = parse_args()
    wr = load_awswrangler()
    boto3_session = create_boto3_session(args.profile_name)

    zeek_log = os.path.expanduser(args.zeek_log)
    log_to_df = LogToDataFrame()
    zeek_df = log_to_df.create_dataframe(zeek_log)
    print("DataFrame Created: {:d} rows...".format(len(zeek_df)))

    # AWS SDK for pandas writes Parquet through pyarrow, so keep the timedelta
    # normalization used by the local Parquet example.
    zeek_df = convert_timedelta_to_str(zeek_df.copy())

    result = wr.s3.to_parquet(
        df=zeek_df,
        path=args.s3_path,
        index=not args.no_index,
        compression="snappy",
        dataset=True,
        mode=args.mode,
        database=args.database,
        table=args.table,
        partition_cols=args.partition_cols,
        sanitize_columns=bool(args.database and args.table),
        boto3_session=boto3_session,
    )

    print("Complete: {:s} --> {:s}".format(zeek_log, args.s3_path))
    print("Files Written: {:d}".format(len(result.get("paths", []))))
