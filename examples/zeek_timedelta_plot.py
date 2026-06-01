"""Plot Zeek timedelta columns with explicit time units."""

import argparse
import os
import sys

# Local imports
from zat.log_to_dataframe import LogToDataFrame
from zat.utils import file_utils, plot_utils

TIME_UNITS = {
    "seconds": 1.0,
    "milliseconds": 1000.0,
    "microseconds": 1000000.0,
}


def convert_duration_to_unit(duration_series, unit):
    """Convert a Pandas timedelta Series into a numeric plotting column."""
    return duration_series.dt.total_seconds() * TIME_UNITS[unit]


if __name__ == "__main__":
    # Pandas stores Zeek interval fields like conn.log duration as timedelta64[ns].
    # Some Pandas/Matplotlib versions do not histogram that dtype directly, so this
    # example converts the duration to explicit numeric units before plotting.

    data_path = file_utils.relative_dir(__file__, "../data")
    default_log = os.path.join(data_path, "conn.log")

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument("zeek_log", nargs="?", default=default_log, help="Specify a Zeek conn.log input file")
    parser.add_argument(
        "-u",
        "--unit",
        choices=sorted(TIME_UNITS),
        default="seconds",
        help="Unit to use for the numeric duration column",
    )
    parser.add_argument("-b", "--bins", type=int, default=20, help="Number of histogram bins")
    parser.add_argument("-o", "--output", type=str, help="Optional image file to write instead of showing the plot")
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print("Unrecognized args: %s" % commands)
        sys.exit(1)

    # File may have a tilde in it
    args.zeek_log = os.path.expanduser(args.zeek_log)
    if args.output:
        args.output = os.path.expanduser(args.output)

    # Create a Pandas dataframe from a Zeek log
    log_to_df = LogToDataFrame()
    zeek_df = log_to_df.create_dataframe(args.zeek_log)

    # The conn.log duration field is a Zeek interval, which ZAT converts to timedelta64[ns].
    if "duration" not in zeek_df:
        print("Could not find a duration column in {:s}".format(args.zeek_log))
        sys.exit(1)

    duration_column = "duration_{:s}".format(args.unit)
    zeek_df[duration_column] = convert_duration_to_unit(zeek_df["duration"], args.unit)

    print(zeek_df[["duration", duration_column]].head())
    print("Plotting {:s} as numeric {:s}".format("duration", args.unit))

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("Please > pip install matplotlib")
        sys.exit(1)

    plot_utils.plot_defaults()
    axis = zeek_df[duration_column].hist(bins=args.bins)
    axis.set_title("Zeek connection duration histogram")
    axis.set_xlabel("Duration ({:s})".format(args.unit))
    axis.set_ylabel("Count")

    if args.output:
        axis.figure.tight_layout()
        axis.figure.savefig(args.output)
        print("Wrote plot: {:s}".format(args.output))
    else:
        plt.show()
