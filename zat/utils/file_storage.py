"""FileStorage class for storing/retrieving bytes to/from persistant storage
      Methods:
        - store(key, bytes): Takes a bytes object as input
        - get(key): Returns a bytes object
"""

import os

try:
    import pyarrow  # noqa F401
    _HAVE_PYARROW = True
except ImportError:
    print('pyarrow not found, $ pip install pyarrow for more tests...')
    _HAVE_PYARROW = False


class FileStorage(object):
    """FileStorage class for storing/retrieving bytes to/from persistant storage
          Methods:
            - store(key, bytes): Takes a bytes object as input
            - get(key): Returns a bytes object
     """

    def __init__(self):
        """FileStorage Initialization"""
        self.tmp_dir = '/tmp/zat_file_storage'
        os.makedirs(self.tmp_dir, exist_ok=True)

    def store(self, key, bytes_buffer):
        """Store the buffer with the associated key"""

        # Write the temporary file
        try:
            filename = self.compute_filename(key)
            tempfile = filename + '.tmp'
            with open(tempfile, 'wb') as fp:
                fp.write(bytes_buffer)
            os.rename(tempfile, filename)
        except (PermissionError, IOError):
            msg = 'FileStorage: could not write to disk!'
            print(msg)
            raise IOError(msg)

    def get(self, key):
        """Retrieve the buffer associated with the given key"""

        # Now see if we can read it off disk (it may have been removed/expired)
        try:
            filename = self.compute_filename(key)
            print('FileStorage: Returning bytes for: {:s}'.format(key))
            with open(filename, 'rb') as fp:
                return fp.read()

        except IOError:
            print('Could not read file for key: {:s}'.format(key))
            return None

    def compute_filename(self, key):
        # Compute the temporary file name
        return os.path.join(self.tmp_dir, key)

    def stored_files(self):
        return [os.path.join(self.tmp_dir, name) for name in os.listdir(self.tmp_dir)]

    @property
    def size(self):
        """Return size of the query/dataframe store"""
        return len(self.stored_files())

    def clear(self):
        """Clear the query/dataframe store"""
        for filename in self.stored_files():
            try:
                os.unlink(filename)
            except IOError:
                print('Could not delete: {:s}'.format(filename))

    def dump(self):
        """Dump the cache key/values (for debugging)"""
        for filename in self.stored_files():
            print(filename)


def test():
    """Test for the FileStorage class"""
    import json
    from io import BytesIO
    import pandas as pd

    # Create some data
    data1 = {'foo': [1, 2, 1, 1, 2, 3], 'name': ['bob', 'bob', 'sue', 'sue', 'jim', 'jim']}
    data2 = {'count': [8, 9, 8, 8, 8, 9], 'name': ['joe', 'sal', 'joe', 'sal', 'joe', 'sal']}
    my_storage = FileStorage()
    my_storage.clear()

    # Serialize the data
    bytes1 = json.dumps(data1).encode('utf-8')
    bytes2 = json.dumps(data2).encode('utf-8')

    # Test storage
    my_storage.store('data1_key', bytes1)
    my_storage.store('data2_key', bytes2)

    # Make sure size is working
    assert my_storage.size == 2

    # Try grabbing a key that doesn't exist
    assert my_storage.get('no key') is None

    # Dump the storage
    my_storage.dump()

    # Retrieve the stored data
    r_data1 = json.loads(my_storage.get('data1_key'))
    r_data2 = json.loads(my_storage.get('data2_key'))
    assert r_data1 == data1
    assert r_data2 == data2

    # Delete our key value entries
    my_storage.clear()
    assert my_storage.size == 0

    # Dump the cache
    my_storage.dump()

    # Now run all the same tests with dataframes (only if pyarrow available)
    if _HAVE_PYARROW:

        # Helper methods
        def dataframe_to_bytes(df):
            bytes_buffer = BytesIO()
            df.to_parquet(bytes_buffer)
            return bytes_buffer.getvalue()

        def dataframe_from_bytes(df_bytes):
            return pd.read_parquet(BytesIO(df_bytes))

        # Create the a dataframe and a DataStore class
        df1 = pd.DataFrame(data={'foo': [1, 2, 1, 1, 2, 3], 'name': ['bob', 'bob', 'sue', 'sue', 'jim', 'jim']})
        df2 = pd.DataFrame(data={'count': [8, 9, 8, 8, 8, 9], 'name': ['joe', 'sal', 'joe', 'sal', 'joe', 'sal']})
        my_storage.clear()

        # Serialize the dataframes
        df1_bytes = dataframe_to_bytes(df1)
        df2_bytes = dataframe_to_bytes(df2)

        # Test storage
        my_storage.store('df1_key', df1_bytes)
        my_storage.store('df2_key', df2_bytes)

        # Make sure size is working
        assert my_storage.size == 2

        # Dump the cache
        my_storage.dump()

        # Retrieve the cached dataframes
        r_df1 = dataframe_from_bytes(my_storage.get('df1_key'))
        r_df2 = dataframe_from_bytes(my_storage.get('df2_key'))
        assert r_df1.equals(df1)
        assert r_df2.equals(df2)

        # Delete our key value entries
        my_storage.clear()
        assert my_storage.size == 0


if __name__ == '__main__':

    # Run the test
    test()
