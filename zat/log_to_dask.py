"""LogToDataFrame: Converts a Zeek log to a Dask DataFrame"""

from typing import Dict, List, Optional, Tuple

try:
    import dask.dataframe as dd
except ImportError:
    print("\npip install dask")

from zat.utils.field_info import get_field_info


class LogToDask:
    """LogToDask: Converts a Zeek log to a Dask DataFrame"""

    def __init__(self):
        self.type_map = {
            "bool": "category",  # Can't hold NaN values in 'bool', so we're going to use category
            "count": "UInt64",
            "int": "Int32",
            "double": "float",
            "time": "float",  # Secondary Processing into datetime
            "interval": "float",  # Secondary processing into timedelta
            "port": "UInt16",
            "addr": "string",
        }

    def create_dataframe(
        self,
        log_filename: str,
        ts_index: bool = True,
        aggressive_category: bool = True,
        usecols: Optional[List[str]] = None,
    ) -> "dd.DataFrame":
        """Create a Dask dataframe from a Bro/Zeek log file
        Args:
           log_filename (string): The full path to the Zeek log
           ts_index (bool): Set the index to the 'ts' field (default = True)
           aggressive_category (bool): convert unknown columns to category (default = True)
           usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # Grab the field information
        field_names, field_types = get_field_info(log_filename=log_filename)
        all_fields = field_names  # We need ALL the fields for later

        # If usecols is set then we'll subset the fields and types
        if usecols:
            # Usecols needs to include ts
            if "ts" not in usecols:
                usecols.append("ts")
            field_types = [t for t, field in zip(field_types, field_names) if field in usecols]
            field_names = [field for field in field_names if field in usecols]

        # Get the appropriate types for the dask Dataframe
        dask_types = self._apply_type_map(field_names, field_types, aggressive_category)

        # Now actually read in the initial dataframe
        self._df = self._get_dataframe(
            log_filename=log_filename, all_fields=all_fields, dtypes=dask_types, usecols=usecols
        )

        # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
        for name, zeek_type in zip(field_names, field_types):
            if zeek_type == "time":
                self._df[name] = dd.to_datetime(self._df[name], unit="s").dt.floor("us")
            if zeek_type == "interval":
                self._df[name] = dd.to_timedelta(self._df[name]).dt.total_seconds()

        # Set the index
        # .empty isn't supported by dask. This condition is a workaround
        if ts_index and len(self._df.columns) > 0:
            try:
                self._df.set_index("ts", inplace=True)
            except KeyError:
                print("Could not find ts/timestamp for index...")
        return self._df

    def _get_dataframe(
        self, log_filename: str, all_fields: List[str], dtypes: Dict, usecols: Optional[List[str]]
    ) -> "dd.DataFrame":
        """Internal Method: Create the initial dataframes by using dask read CSV (primary types correct)"""
        return dd.read_csv(
            log_filename, sep="\t", names=all_fields, usecols=usecols, dtype=dtypes, comment="#", na_values="-"
        )

    def _apply_type_map(
        self, column_names: List[str], column_types: List[str], aggressive_category: bool = True, verbose: bool = False
    ) -> Tuple[List[str], List[str]]:
        """Given a set of names and types, construct a Dictionary to be used
        as the dask read_csv dtypes argument"""

        # Aggressive Category means that types not in the current type_map are
        # mapped to a 'category' if aggressive_category is False then they
        # are mapped to an 'object' type
        unknown_type = "category" if aggressive_category else "object"

        dask_types = {}
        for name, zeek_type in zip(column_names, column_types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity Check
            if not item_type:
                # UID/FUID/GUID always gets mapped to object
                if "uid" in name:
                    item_type = "object"
                else:
                    if verbose:
                        print("Could not find type for {:s} using {:s}...".format(zeek_type, unknown_type))
                    item_type = unknown_type

            # Set the dask type
            dask_types[name] = item_type

        # Return the dictionary of name: type
        return dask_types


# Simple test of the functionality
def test():
    """Test for LogToDataFrame Class"""
    import os

    import pytest

    try:
        import dask.dataframe  # noqa: F401
    except ImportError:
        pytest.skip("pip install dask")

    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, "../data")
    log_path = os.path.join(data_path, "conn.log")

    # create_dataframe it to a Pandas DataFrame
    log_to_df = LogToDask()
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    # Test a bunch
    tests = [
        "app_stats.log",
        "dns.log",
        "http.log",
        "notice.log",
        "tor_ssl.log",
        "conn.log",
        "dhcp_002.log",
        "files.log",
        "smtp.log",
        "weird.log",
        "ftp.log",
        "ssl.log",
        "x509.log",
    ]
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print("Testing: {:s}...".format(log_path))
        my_df = log_to_df.create_dataframe(log_path)
        print(my_df.head())
        print(my_df.dtypes)

    # Test out usecols arg
    conn_path = os.path.join(data_path, "conn.log")
    my_df = log_to_df.create_dataframe(
        conn_path, usecols=["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes"]
    )

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, "http_empty.log")
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print("LogToDataFrame Test successful!")
