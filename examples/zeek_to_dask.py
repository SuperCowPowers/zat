"""Zeek log to Dask Dataframe Example"""

import os

from zat.log_to_dask import LogToDask
from zat.utils import file_utils

# Grab a test file
data_path = file_utils.relative_dir(__file__, "../data")
log_path = os.path.join(data_path, "conn.log")

# Create a Dask dataframe from a Zeek log
log_to_df = LogToDask()
dask_df = log_to_df.create_dataframe(log_path)

# Print out the head of the dataframe
print(dask_df.head())

# Print out the types of the columns
print(dask_df.dtypes)
