"""DataFrameToMatrix: Class that converts a DataFrame to a Numpy Matrix (ndarray)"""
from __future__ import print_function

# Third Party
import pandas as pd
import numpy as np


class DataFrameToMatrix(object):
    """DataFrameToMatrix: Class that converts a DataFrame to a Numpy Matrix (ndarray)
        Notes:
            fit_transform: Does a fit and a transform and returns the transformed matrix
            transform: Based on previous fit parameters returns the transformed matrix
        More Info: https://supercowpowers.github.io/zat/dataframe_to_matrix.html

        # Nullable integer arrays are currently not handled by Numpy
        # Cast Nullable integer arrays to float32
        null_int_types = [pd.UInt16Dtype, pd.UInt32Dtype, pd.UInt64Dtype, pd.Int64Dtype]
        for col in _internal_df:
            if type(_internal_df[col].dtype) in null_int_types:
                _internal_df[col] = _internal_df[col].astype(np.float32)

    """
    def __init__(self):
        """Initialize the DataFrameToMatrix class"""
        self.column_names = None
        self.norm_map = {}
        self.dtype_map = {}
        self.nan_replace = -999

    def fit_transform(self, input_df, normalize=True, nan_replace=-999, copy=True):
        """Convert the dataframe to a matrix (numpy ndarray)
        Args:
            input_df (dataframe): The dataframe to convert
            normalize (bool): Boolean flag to normalize numeric columns (default=True)
        """
        self.nan_replace = nan_replace

        # Copy the dataframe (if wanted)
        _internal_df = input_df.copy() if copy else input_df

        # Convert object columns to categorical
        self.object_to_categorical(_internal_df)

        # Convert categorical NaNs
        self.fit_category_nans(_internal_df)

        # Lock categories to specific values (important for train/predict consistency)
        self.lock_categorical(_internal_df)

        # Sanity Check
        self.sanity_check_categorical(_internal_df)

        # Normalize numeric columns (mean normalize, sometimes called 'standardizing')
        if normalize:
            self.normalize_numeric(_internal_df)

        # Remove any numerical NaNs (categorical NaNs were removed above)
        for column in _internal_df.select_dtypes(include='number').columns:
            _internal_df[column].fillna(self.nan_replace, inplace=True)

        # Drop any columns that aren't numeric or categorical
        _internal_df = _internal_df.select_dtypes(include=['number', 'category'])

        # Capture all the column/dtype information from the dataframe
        self.column_names = _internal_df.columns.to_list()
        for column in _internal_df.columns:
            self.dtype_map[column] = _internal_df[column].dtype

        # Now with every thing setup, call the dummy_encoder, convert to ndarray and return
        return pd.get_dummies(_internal_df).to_numpy(dtype=np.float32)

    def transform(self, input_df, copy=True):
        """Convert the dataframe to a matrix (numpy ndarray)
        Args:
            input_df (dataframe): The dataframe to convert
        """

        # Make sure we have the same columns in the right order
        # Copy the dataframe (if wanted)
        _internal_df = input_df[self.column_names].copy() if copy else input_df[self.column_names]

        # Convert all columns to the proper dtypes
        for column, dtype in self.dtype_map.items():
            _internal_df[column] = _internal_df[column].astype(dtype)

        # Convert any categorical NaNs to a 'NaN' category
        self.transform_category_nans(_internal_df)

        # Normalize any numeric columns
        for column, (smin, smax) in self.norm_map.items():
            print('Normalizing column {:s}...'.format(column))
            _internal_df[column] = (_internal_df[column] - smin) / (smax - smin)

        # Remove any numerical NaNs (categorical NaNs were removed above)
        for column in _internal_df.select_dtypes(include='number').columns:
            _internal_df[column].fillna(self.nan_replace, inplace=True)

        # Now with every thing setup, call the dummy_encoder, convert to ndarray and return
        return pd.get_dummies(_internal_df).to_numpy(dtype=np.float32)

    @staticmethod
    def fit_category_nans(df):
        """ONLY FIT: Convert np.NaNs to a category 'NaN'"""
        for column in df.select_dtypes(include=['category']).columns:
            if df[column].isnull().any():
                df[column].cat.add_categories('NaN', inplace=True)
                df[column].fillna('NaN', inplace=True)

    @staticmethod
    def transform_category_nans(df):
        """ONLY TRANSFORM: Convert np.NaNs to a category 'NaN'"""
        for column in df.select_dtypes(include=['category']).columns:
            if 'NaN' in df[column].cat.categories:
                df[column].fillna('NaN', inplace=True)

    @staticmethod
    def object_to_categorical(df):
        """Run a heuristic on the object columns to determine whether it contains categorical values
           if the heuristic decides it's categorical then the type of the column is changed
        Args:
            df (dataframe): The dataframe to check for categorical data
        Returns:
            None but the dataframe columns are modified
        """

        # Loop through each column that might be converable to categorical
        for column in df.select_dtypes(include='object').columns:

            # If we don't have too many unique values convert the column
            if df[column].nunique() < 20:
                print('Changing column {:s} to category...'.format(column))
                df[column] = pd.Categorical(df[column])

    @staticmethod
    def lock_categorical(df):
        """Lock the categorical column types to a specific ordered list of categories
        Args:
            df (dataframe): The dataframe to lock categorical columns
        Returns:
            None but note that the dataframe is modified to 'lock' the categorical columns
        """
        for column in df.select_dtypes(include='category').columns:
            df[column] = pd.Categorical(df[column], categories=df[column].unique())

    @staticmethod
    def sanity_check_categorical(df):
        """Sanity check for 'dimensionality explosion' on categorical types
        Args:
            df (dataframe): The dataframe to check the categorical columns
        Returns:
            None
        """
        for column in df.select_dtypes(include='category').columns:
            # Give warning on category types will LOTs of values
            num_unique = df[column].nunique()
            if num_unique > 20:
                print('WARNING: {:s} will expand into {:d} dimensions! Should not include in feature set!'.format(column, num_unique))

    def normalize_numeric(self, df):
        """Normalize (mean normalize) the numeric columns in the dataframe
        Args:
            df (dataframe): The dataframe to normalize
        Returns:
            None but note that the numeric columns of the dataframe are modified
        """
        for column in df.select_dtypes(include='number').columns:
            print('Normalizing column {:s}...'.format(column))
            df[column] = self._normalize_series(df[column])

    def _normalize_series(self, series):
        smin = series.min()
        smax = series.max()

        # Check for div by 0
        if smax - smin == 0:
            print('Cannot normalize series (div by 0) so not normalizing...')
            return series

        # Capture the normalization info and return the normalize series
        self.norm_map[series.name] = (smin, smax)
        return (series - smin) / (smax - smin)


# Simple test of the functionality
def test():
    """Test for DataFrameToMatrix Class"""
    import os
    import pickle
    from tempfile import NamedTemporaryFile
    import numpy.testing as np_test_utils
    pd.set_option('display.width', 1000)

    test_df = pd.DataFrame(
        {'A': pd.Categorical(['a', 'b', 'c', 'a'], ordered=True),
         'B': pd.Categorical(['a', 'b', 'c', 'a'], ordered=False),
         'C': pd.Categorical(['a', 'b', 'z', 'a'], categories=['a', 'b', 'z', 'd']),
         'D': [1, 2, 3, 4],
         'E': ['w', 'x', 'y', 'z'],
         'F': [1.1, 2.2, 3.3, 4.4],
         'G': pd.to_datetime([0, 1, 2, 3]),
         'H': [True, False, False, True]
         }
    )
    test_df2 = pd.DataFrame(
        {'A': pd.Categorical(['a', 'b', 'b', 'a'], ordered=True),
         'B': pd.Categorical(['a', 'b', 'd', 'a'], ordered=False),
         'C': pd.Categorical(['a', 'b', 'z', 'y'], categories=['a', 'b', 'z', 'd']),
         'D': [1, 2, 3, 7],
         'E': ['w', 'x', 'z', 'foo'],
         'F': [1.1, 2.2, 3.3, 4.4],
         'H': [True, False, False, False]
         }
    )

    # Copy the test_df for testing later
    copy_test_df = test_df.copy()

    # Test the transformation from dataframe to numpy ndarray and back again
    to_matrix = DataFrameToMatrix()
    print('FIT-TRANSFORM')
    matrix = to_matrix.fit_transform(test_df)
    print('TRANSFORM')
    matrix_test = to_matrix.transform(test_df)

    # These two matrices should be the same
    np_test_utils.assert_equal(matrix, matrix_test)

    # Assert that the dataframe we passed in didn't change
    copy_test_df.equals(test_df)

    # Test that the conversion gives us the same columns on a df with different category values
    # This also tests NaN in a category column
    print('TRANSFORM2')
    matrix2 = to_matrix.transform(test_df2)
    assert matrix.shape == matrix2.shape

    # First two ROWS should be the same
    np_test_utils.assert_equal(matrix[0], matrix2[0])
    np_test_utils.assert_equal(matrix[1], matrix2[1])

    # Test normalize
    to_matrix_norm = DataFrameToMatrix()
    print('FIT-TRANSFORM')
    norm_matrix = to_matrix_norm.fit_transform(test_df)
    print(norm_matrix)
    assert(norm_matrix[:, 0].min() == 0)
    assert(norm_matrix[:, 0].max() == 1)

    # Make sure normalize 'does the right thing' when doing transform
    print('TRANSFORM')
    norm_matrix2 = to_matrix_norm.transform(test_df2)
    assert(norm_matrix2[:, 0].min() == 0)
    assert(norm_matrix2[:, 0].max() == 2)    # Normalization is based on FIT range

    # Test div by zero in normalize
    test_df3 = test_df2.copy()
    test_df3['D'] = [1, 1, 1, 1]
    print('FIT-TRANSFORM')
    norm_matrix3 = to_matrix_norm.fit_transform(test_df3)
    assert(norm_matrix3[:, 0].min() == 1)
    assert(norm_matrix3[:, 0].max() == 1)

    # Test serialization
    temp = NamedTemporaryFile(delete=False)
    pickle.dump(to_matrix, temp)
    temp.close()

    # Deserialize and test
    to_matrix_from_disk = pickle.load(open(temp.name, 'rb'))
    print('TRANSFORM')
    matrix3 = to_matrix_from_disk.transform(test_df)
    print('TRANSFORM')
    matrix4 = to_matrix_from_disk.transform(test_df2)
    np_test_utils.assert_equal(matrix, matrix3)
    np_test_utils.assert_equal(matrix2, matrix4)

    # Remove the temporary file
    os.unlink(temp.name)

    # Try 'nullable' integer arrays
    null_df = test_df2.copy()
    null_df['I'] = pd.Series([10, 11, 12, np.NaN], dtype='UInt64')
    print('FIT-TRANSFORM')
    matrix = to_matrix.fit_transform(null_df)
    print('TRANSFORM')
    matrix_test = to_matrix.transform(null_df)

    # These two matrices should be the same
    np_test_utils.assert_equal(matrix, matrix_test)

    # Now actually try the matrix with a scikit-learn algo
    from sklearn.cluster import KMeans
    to_matrix = DataFrameToMatrix()
    my_matrix = to_matrix.fit_transform(test_df)
    kmeans = KMeans(n_clusters=2).fit_predict(my_matrix)

    # Now we can put our ML results back onto our dataframe!
    test_df['cluster'] = kmeans
    cluster_groups = test_df.groupby('cluster')

    # Now print out the details for each cluster
    for key, group in cluster_groups:
        print('Rows in Cluster: {:d}'.format(len(group)))
        print(group.head(), '\n')
    del test_df['cluster']

    # Now we're going to intentionally introduce NaNs in the categorical output just to see what happens
    to_matrix = DataFrameToMatrix()
    _ = to_matrix.fit_transform(test_df)
    my_matrix2 = to_matrix.transform(test_df2)
    kmeans = KMeans(n_clusters=2).fit_predict(my_matrix2)

    # Now we can put our ML results back onto our dataframe!
    test_df2['cluster'] = kmeans
    cluster_groups = test_df2.groupby('cluster')

    # Now print out the details for each cluster
    for key, group in cluster_groups:
        print('Rows in Cluster: {:d}'.format(len(group)))
        print(group.head(), '\n')


if __name__ == "__main__":
    test()
