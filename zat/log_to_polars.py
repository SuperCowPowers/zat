"""LogToDataFrame: Converts a Zeek log to a Polars DataFrame"""

# Third Party
from typing import Dict, Optional, List, Tuple

try:
    import polars as pl
except ImportError:
    print("\npip install polars")


# Local
from zat.utils.field_info import get_field_info


class LogToPolars:
    """LogToPolats: Converts a Zeek log to a Polars DataFrame"""

    def __init__(self):
        # Polars data types : https://docs.pola.rs/api/python/stable/reference/datatypes.html
        self.type_map = {
            "str": pl.String,
            "addr": pl.String,
            "table[string]": pl.String,
            "bool": pl.Categorical,
            "double": pl.Float64,
            "time": pl.Float64,
            "interval": pl.Float64,
            "int": pl.Int32,
            "count": pl.UInt64,
            "port": pl.UInt16,
            "enum": pl.Categorical,
        }

    def create_dataframe(self, log_filename: str, usecols: Optional[List[str]] = None) -> "pl.DataFrame":
        """Create a Polars dataframe from a Bro/Zeek log file
        Args:
           log_filename (string): The full path to the Zeek log
           usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # 1. Get field infos.
        field_names, field_types = get_field_info(log_filename=log_filename)
        all_fields = field_names

        # 2. Convert zeek types to polars types.
        #    Replace old types from FieldInfos struct with the converted ones.
        type_map = self._apply_type_map(field_names, field_types)

        # 3. Get only the specified columns
        if usecols:
            field_types = [t for t, field in zip(field_types, field_names) if field in usecols]
            field_names = [field for field in field_names if field in usecols]

        # 3. Get dataframe.
        self._df = self._get_dataframe(
            log_filename=log_filename, all_fields=all_fields, dtypes=type_map, usecols=usecols
        )

        # 4. Convert time type.
        time_cols = [name for name, zt in zip(field_names, field_types) if zt == "time"]
        interval_cols = [name for name, zt in zip(field_names, field_types) if zt == "interval"]

        if time_cols:
            self._df = self._df.with_columns([pl.from_epoch(pl.col(c), time_unit="s") for c in time_cols])

        if interval_cols:
            self._df = self._df.with_columns([(pl.col(c) * 1000).cast(pl.Duration("ms")) for c in interval_cols])

        return self._df

    def _get_dataframe(
        self, log_filename: str, all_fields: List[str], dtypes: Dict, usecols: Optional[List[str]] = None
    ) -> "pl.DataFrame":
        """Internal Method: Create the initial dataframes by using Polars read CSV (primary types correct)"""
        return pl.read_csv(
            log_filename,
            separator="\t",
            has_header=False,
            new_columns=all_fields,
            columns=usecols,
            schema_overrides=dtypes,
            comment_prefix="#",
            null_values=["-", "NA", ""],
        )

    def _apply_type_map(self, column_names: List[str], column_types: List[str]) -> Tuple[List[str], List[str]]:
        polars_types_map = {}
        for name, zeek_type in zip(column_names, column_types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity Check
            if not item_type:
                item_type = pl.String

            # Set the pandas type
            polars_types_map[name] = item_type

        return polars_types_map


# Simple test of the functionality
def test():
    """Test for LogToDataFrame Class"""
    import os

    import pytest

    try:
        import polars  # noqa: F401
    except ImportError:
        pytest.skip("pip install polars")

    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, "../data")
    log_path = os.path.join(data_path, "conn.log")

    # create_dataframe it to a Pandas DataFrame
    log_to_df = LogToPolars()
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

    # Test an empty log (a log with header/close but no data rows)
    # log_path = os.path.join(data_path, 'http_empty.log')
    # my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print("LogToDataFrame Test successful!")
