"""Zeek log to Polars Dataframe Example"""

import os

from zat.log_to_polars import LogToPolars
from zat.utils import file_utils

# Grab a test file
data_path = file_utils.relative_dir(__file__, "../data")
log_path = os.path.join(data_path, "conn.log")

# Create a Polars dataframe from a Zeek log
log_to_df = LogToPolars()
polars_df = log_to_df.create_dataframe(log_path)

# Print out the head of the dataframe
print(polars_df.head())

# Print out the types of the columns
print(polars_df.dtypes)
