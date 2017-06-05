""" DataFrame Cache Class: The class provides a caching mechanism for a Pandas DataFrame """
from __future__ import print_function
import time
from collections import deque
import pandas as pd


class DataFrameCache(object):
    """DataFrameCache: The class provides a caching mechanism for a Pandas DataFrame.

        Args:
            max_cache_size (int): Maximum size of dataframe cache (default=10000)
            max_cache_time (int): Time to keep rows in cache (default=60 seconds)
    """
    def __init__(self, max_cache_size=100000, max_cache_time=60):
        """Initialize the DataFrameCache class"""
        self.max_size = max_cache_size
        self.max_time = max_cache_time
        self.row_deque = deque(maxlen=self.max_size)
        self.time_deque = deque(maxlen=self.max_size)
        self._dataframe = pd.DataFrame()

    def add_row(self, row):
        """Add a row to the DataFrameCache class"""
        self.add_rows([row])

    def add_rows(self, list_of_rows):
        """Add a list of rows to the DataFrameCache class"""
        for row in list_of_rows:
            self.row_deque.append(row)
            self.time_deque.append(time.time())
        # Update the data structure
        self.update()

    def dataframe(self):
        """Return a DataFrame with the current window of data
           Note: Only call this when you want the dataframe to be reconstructed"""
        self.update()
        return pd.DataFrame(list(self.row_deque))

    def update(self):
        """Update the deque, removing rows based on time"""
        expire_time = time.time() - self.max_time
        while self.row_deque and self.time_deque[0] < expire_time:
            self.row_deque.popleft()  # FIFO
            self.time_deque.popleft()


# Simple test of the functionality
def test():
    """Test for DataFrameCache Class"""
    import copy

    df_cache = DataFrameCache(max_cache_size=10, max_cache_time=1)  # Make it small and short for testing

    # Make some fake data
    base_row = {'id': 0, 'foo': 'bar', 'port': 80, 'protocol': 17}

    # Create an array of test rows
    test_data = []
    for i in range(20):
        row = copy.deepcopy(base_row)
        row['id'] = i
        test_data.append(row)

    # Add rows
    df_cache.add_rows(test_data)

    # Make sure the cache size is working properly
    my_df = df_cache.dataframe()
    assert len(my_df) == 10
    assert my_df.iloc[0]['id'] == 10  # This means the deque is proper FIFO

    # Now test time expiration
    time.sleep(1)
    my_df = df_cache.dataframe()
    assert len(my_df) == 0


if __name__ == "__main__":
    test()
