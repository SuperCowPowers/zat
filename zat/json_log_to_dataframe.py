"""JSONLogToDataFrame: Converts a Zeek JSON log to a Pandas DataFrame"""

import os
from collections.abc import Hashable

# Third Party
import pandas as pd

# Local Imports


class JSONLogToDataFrame(object):
    """JSONLogToDataFrame: Converts a Zeek JSON log to a Pandas DataFrame
    Notes:
        Zeek JSON logs do not include a #types header, so this class uses a
        best-effort column map for common Zeek fields. You can pass
        column_types to override or extend the default mapping.
    """

    DEFAULT_ZEEK_TYPES = {
        "ts": "time",
        "duration": "interval",
        "rtt": "interval",
        "id.orig_p": "port",
        "id.resp_p": "port",
        "trans_id": "count",
        "qclass": "count",
        "qtype": "count",
        "rcode": "count",
        "Z": "count",
        "orig_bytes": "count",
        "resp_bytes": "count",
        "missed_bytes": "count",
        "orig_pkts": "count",
        "orig_ip_bytes": "count",
        "resp_pkts": "count",
        "resp_ip_bytes": "count",
        "AA": "bool",
        "TC": "bool",
        "RD": "bool",
        "RA": "bool",
        "rejected": "bool",
        "local_orig": "bool",
        "local_resp": "bool",
        "proto": "category",
        "service": "category",
        "conn_state": "category",
        "history": "category",
        "qclass_name": "category",
        "qtype_name": "category",
        "rcode_name": "category",
    }

    def __init__(self):
        """Initialize the JSONLogToDataFrame class"""

        self.type_map = {
            "bool": "boolean",
            "count": "UInt64",
            "int": "Int64",
            "double": "float",
            "port": "UInt16",
        }

    def create_dataframe(self, log_filename, ts_index=True, aggressive_category=True, maxrows=None, column_types=None):
        """Create a Pandas dataframe from a Zeek JSON log file
        Args:
           log_filename (string): The full path to the Zeek log
           ts_index (bool): Set the index to the 'ts' field (default = True)
           aggressive_category (bool): convert unknown string columns to category (default = True)
           maxrows: Read in a subset of rows for testing/inspecting (default = None)
           column_types (dict): Optional column-to-Zeek-type mapping. Supported Zeek
               types include time, interval, bool, count, int, double, port, and category.
        """
        # Sanity check the filename
        if not os.path.isfile(log_filename):
            print(f"Could not find file: {log_filename}")
            return pd.DataFrame()

        # Read in the JSON file as a dataframe
        _df = pd.read_json(log_filename, nrows=maxrows, lines=True)

        # Apply type information where JSON logs do not provide a #types header.
        resolved_types = dict(self.DEFAULT_ZEEK_TYPES)
        if column_types:
            resolved_types.update(column_types)
        self._apply_column_types(_df, resolved_types, aggressive_category)

        # Set the index
        if "ts" in _df.columns and ts_index:
            _df.set_index("ts", inplace=True)

        # Okay our dataframe should be ready to go
        return _df

    def _apply_column_types(self, dataframe, column_types, aggressive_category):
        """Apply Zeek-informed dtypes to a JSON dataframe."""
        for column, zeek_type in column_types.items():
            if column not in dataframe.columns:
                continue

            if zeek_type == "time":
                dataframe[column] = pd.to_datetime(dataframe[column], unit="s")
            elif zeek_type == "interval":
                dataframe[column] = pd.to_timedelta(dataframe[column], unit="s")
            elif zeek_type == "category":
                dataframe[column] = dataframe[column].astype("category")
            elif zeek_type in self.type_map:
                dataframe[column] = pd.to_numeric(dataframe[column], errors="coerce").astype(self.type_map[zeek_type])
            else:
                dataframe[column] = dataframe[column].astype(zeek_type)

        if not aggressive_category:
            return

        for column in dataframe.select_dtypes(include=["object", "str", "string"]).columns:
            if self._is_identifier_column(column) or not self._can_be_category(dataframe[column]):
                continue
            dataframe[column] = dataframe[column].astype("category")

    @staticmethod
    def _is_identifier_column(column):
        column_parts = column.split(".")
        return column in {"uid", "fuid"} or column_parts[-1] in {"uid", "fuid", "guid"}

    @staticmethod
    def _can_be_category(series):
        non_null = series.dropna()
        if non_null.empty:
            return True
        return non_null.map(lambda value: isinstance(value, Hashable)).all()


# Simple test of the functionality
def test():
    """Test for JSONLogToDataFrame Class"""
    import os

    pd.set_option("display.width", 1000)
    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, "../data/json")
    log_path = os.path.join(data_path, "conn.log")

    # Convert it to a Pandas DataFrame
    log_to_df = JSONLogToDataFrame()
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    # Test a bunch
    tests = [
        "capture_loss.log",
        "dhcp.log",
        "http.log",
        "ntp.log",
        "smb_mapping.log",
        "weird.log",
        "conn.log",
        "dns.log",
        "kerberos.log",
        "packet_filter.log",
        "ssl.log",
        "x509.log",
        "dce_rpc.log",
        "files.log",
        "loaded_scripts.log",
        "smb_files.log",
        "stats.log",
    ]
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print("Testing: {:s}...".format(log_path))
        my_df = log_to_df.create_dataframe(log_path)
        print(my_df.head())
        print(my_df.dtypes)

    # Test out maxrows arg
    conn_path = os.path.join(data_path, "conn.log")
    my_df = log_to_df.create_dataframe(conn_path, maxrows=3)
    print(my_df.head())
    assert len(my_df) == 3

    # Test JSON type inference
    conn_df = log_to_df.create_dataframe(conn_path, ts_index=False)
    assert str(conn_df["ts"].dtype).startswith("datetime64")
    assert str(conn_df["duration"].dtype) == "timedelta64[ns]"
    assert str(conn_df["id.orig_p"].dtype) == "UInt16"
    assert str(conn_df["orig_bytes"].dtype) == "UInt64"
    assert str(conn_df["proto"].dtype) == "category"
    assert str(conn_df["conn_state"].dtype) == "category"
    assert str(conn_df["uid"].dtype) != "category"

    dns_path = os.path.join(data_path, "dns.log")
    dns_df = log_to_df.create_dataframe(dns_path, ts_index=False)
    assert str(dns_df["rtt"].dtype) == "timedelta64[ns]"
    assert str(dns_df["qtype"].dtype) == "UInt64"
    assert str(dns_df["AA"].dtype) == "boolean"
    assert str(dns_df["qtype_name"].dtype) == "category"
    assert str(dns_df["answers"].dtype) != "category"

    custom_df = log_to_df.create_dataframe(
        conn_path, ts_index=False, aggressive_category=False, column_types={"uid": "category"}
    )
    assert str(custom_df["uid"].dtype) == "category"

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, "http_empty.log")
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print("JSONLogToDataFrame Test successful!")


if __name__ == "__main__":
    # Run the test for easy testing/debugging

    # Setup Pandas output options
    pd.options.display.max_colwidth = 20
    pd.options.display.max_columns = 10
    test()
