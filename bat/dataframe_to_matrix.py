"""DataFrameToMatrix: Convert a DataFrame to a Numpy Matrix (ndarray) Class"""
from __future__ import print_function

# Third Party
import pandas as pd
import numpy as np

# Local imports
from bat.utils import dummy_encoder


class DataFrameToMatrix(object):
    """DataFrameToMatrix: Convert a DataFrame to a Numpy Matrix (ndarray) Class
        Notes:
            fit_transform: Does a fit and a transform and returns the transformed matrix
            transform: Based on previous fit parameters returns the transformed matrix
    """
    def __init__(self):
        """Initialize the DataFrameToMatrix class"""
        self.column_names = None
        self.cat_columns = None
        self.normalize = True
        self.norm_map = {}
        self.dummy_encoder = dummy_encoder.DummyEncoder()

    def fit_transform(self, input_df, normalize=True):
        """Convert the dataframe to a matrix (numpy ndarray)
        Args:
            input_df (dataframe): The dataframe to convert
            normalize (bool): Boolean flag to normalize numeric columns (default=True)
        """
        # Shallow copy the dataframe (we'll be making changes to some columns)
        _df = input_df.copy(deep=False)

        # Set class variables that will be used both now and later for transform
        self.normalize = normalize

        # Convert columns that are probably categorical
        self.convert_to_categorical(_df)

        # First check for columns that are explicitly categorical
        self.cat_columns = _df.select_dtypes(include=['category']).columns.tolist()

        # Remove any columns that aren't bool/int/float/category
        _df = _df.select_dtypes(include=['bool', 'int', 'float', 'category'])

        # Normalize any numeric columns if normalize specified
        if self.normalize:
            for column in list(_df.select_dtypes(include=[np.number]).columns.values):
                print('Normalizing column {:s}...'.format(column))
                _df[column], _min, _max = self._normalize_series(_df[column])
                self.norm_map[column] = (_min, _max)

        # Now that categorical columns are setup call the dummy_encoder
        return self.dummy_encoder.fit_transform(_df)

    def transform(self, input_df):
        """Convert the dataframe to a matrix (numpy ndarray)
        Args:
            input_df (dataframe): The dataframe to convert
        """

        # Shallow copy the dataframe (we'll be making changes to some columns)
        _df = input_df.copy(deep=False)

        # Convert all columns that are/should be categorical
        for column in self.cat_columns:

            # Sanity check
            if column not in _df:
                raise RuntimeError('Required column {:s} not found'.format(column))

            # If the column isn't already a category then change it
            if _df[column].dtype == 'object':
                print('Changing column {:s} to category'.format(column))
                _df[column] = pd.Categorical(_df[column])

        # Remove any columns that aren't bool/int/float/category
        _df = _df.select_dtypes(include=['bool', 'int', 'float', 'category'])

        # Normalize any numeric columns if normalize specified
        if self.normalize:
            for column in list(_df.select_dtypes(include=[np.number]).columns.values):
                print('Normalizing column {:s}...'.format(column))
                smin, smax = self.norm_map[column]
                _df[column] = (_df[column] - smin) / (smax - smin)

        # Now that categorical columns are setup call the dummy_encoder
        return self.dummy_encoder.transform(_df)

    @staticmethod
    def convert_to_categorical(df):
        """Run a heuristic on the columns of the dataframe to determine whether it contains categorical values
           if the heuristic decides it's categorical then the type of the column is changed
        Args:
            df (dataframe): The dataframe to check for categorical data
        """
        might_be_categorical = df.select_dtypes(include=[object]).columns.tolist()
        for column in might_be_categorical:
            if df[column].nunique() < 20:

                # Convert the column
                print('Changing column {:s} to category...'.format(column))
                df[column] = pd.Categorical(df[column])

    @staticmethod
    def _normalize_series(series):
        smin = series.min()
        smax = series.max()
        if smax - smin == 0:
            print('Cannot normalize series (div by 0) so not normalizing...')
            smin = 0
            smax = 1
        return (series - smin) / (smax - smin), smin, smax


# Simple test of the functionality
def test():
    """Test for DataFrameToMatrix Class"""
    import os
    import pickle
    from tempfile import NamedTemporaryFile
    import numpy.testing as np_test_utils

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
    matrix = to_matrix.fit_transform(test_df)
    matrix_test = to_matrix.transform(test_df)

    # These two matrices should be the same
    np_test_utils.assert_equal(matrix, matrix_test)

    # Assert that the dataframe we passed in didn't change
    copy_test_df.equals(test_df)

    # Test that the conversion gives us the same columns on a df with different category values
    matrix2 = to_matrix.transform(test_df2)
    assert matrix.shape == matrix2.shape

    # First two ROWS should be the same
    np_test_utils.assert_equal(matrix[0], matrix2[0])
    np_test_utils.assert_equal(matrix[1], matrix2[1])

    # Test normalize
    to_matrix_norm = DataFrameToMatrix()
    norm_matrix = to_matrix_norm.fit_transform(test_df)
    print(norm_matrix)
    assert(norm_matrix[:, 0].min() == 0)
    assert(norm_matrix[:, 0].max() == 1)

    # Make sure normalize 'does the right thing' when doing transform
    norm_matrix2 = to_matrix_norm.transform(test_df2)
    assert(norm_matrix2[:, 0].min() == 0)
    assert(norm_matrix2[:, 0].max() == 2)    # Normalization is based on FIT range

    # Test div by zero in normalize
    test_df3 = test_df2.copy()
    test_df3['D'] = [1, 1, 1, 1]
    norm_matrix3 = to_matrix_norm.fit_transform(test_df3)
    assert(norm_matrix3[:, 0].min() == 1)
    assert(norm_matrix3[:, 0].max() == 1)

    # Test serialization
    temp = NamedTemporaryFile(delete=False)
    pickle.dump(to_matrix, temp)
    temp.close()

    # Deserialize and test
    to_matrix_from_disk = pickle.load(open(temp.name, 'rb'))
    matrix3 = to_matrix_from_disk.transform(test_df)
    matrix4 = to_matrix_from_disk.transform(test_df2)
    np_test_utils.assert_equal(matrix, matrix3)
    np_test_utils.assert_equal(matrix2, matrix4)

    # Remove the temporary file
    os.unlink(temp.name)


if __name__ == "__main__":
    test()
