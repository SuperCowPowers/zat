"""DataFrameToMatrix: Convert a DataFrame to a Numpy Matrix (ndarray) Class"""
from __future__ import print_function

# Third Party
import pandas as pd

# Local imports
from brothon.analysis import dummy_encoder


class DataFrameToMatrix(object):
    """DataFrameToMatrix: Convert a DataFrame to a Numpy Matrix (ndarray) Class
        Notes:
            fit_transform: Does a fit on the transform and returns a transformed matrix
            transform: Based on previous fit parameters returns a transformed matrix
    """
    def __init__(self):
        """Initialize the DataFrameToMatrix class"""
        self.column_names = None
        self.cat_columns = None
        self.exclude_columns = None
        self.dummy_encoder = dummy_encoder.DummyEncoder()

    def fit_transform(self, input_df, exclude_columns=None):
        """Convert the dataframe to a matrix (numpy ndarray)
        Args:
            df (dataframe): The dataframe to convert
            exclude_columns (list): A list of column names to exclude
        """

        # Do a shallow copy the dataframe and exclude any columns not wanted
        self.exclude_columns = exclude_columns or []
        df = input_df.drop(self.exclude_columns)

        # First check for columns that are explicitly categorical
        self.cat_columns = df.select_dtypes(include=['category']).columns.tolist()

        # Next check for columns that might be categorical
        might_be_categorical = df.select_dtypes(include=[object]).columns.tolist()
        for column in might_be_categorical:
            if self._probably_categorical(df[column]):

                # Add the category columns
                self.cat_columns.append(column)

                # Convert the column
                print('Changing column {:s} to category'.format(column))
                df[column] = pd.Categorical(df[column])

        # Remove any columns that aren't bool/int/float/category
        df = df.select_dtypes(include=['bool', 'int', 'float', 'category'])

        # Now that categorical columns are setup call the dummy_encoder
        return self.dummy_encoder.fit_transform(df)

    def transform(self, input_df):
        """Convert the dataframe to a matrix (numpy ndarray)
        Args:
            df (dataframe): The dataframe to convert
            exclude_columns (list): A list of column names to exclude
        """

        # Do a shallow copy the dataframe and exclude any columns not wanted
        df = input_df.drop(self.exclude_columns)

        # Convert all columns that are/should be categorical
        for column in self.cat_columns:

            # Sanity check
            if column not in df:
                raise RuntimeError('Required column {:s} not found'.format(column))

            # If the column isn't already a category then change it
            if df[column].dtype == 'object':
                print('Changing column {:s} to category'.format(column))
                df[column] = pd.Categorical(df[column])

        # Remove any columns that aren't bool/int/float/category
        df = df.select_dtypes(include=['bool', 'int', 'float', 'category'])

        # Now that categorical columns are setup call the dummy_encoder
        return self.dummy_encoder.transform(df)

    @staticmethod
    def _probably_categorical(series):
        """Run a heuristic on the series to determine whether it contains categorical values
        Args:
            series (dataframe series): The series to check for categorical data
        """
        return series.nunique() < 10


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
         'G': pd.to_datetime([0,1,2,3]),
         'H': [True, False, False, True]
         }
    )
    test_df2 = pd.DataFrame(
        {'A': pd.Categorical(['a', 'b', 'b', 'a'], ordered=True),
         'B': pd.Categorical(['a', 'b', 'd', 'a'], ordered=False),
         'C': pd.Categorical(['a', 'b', 'z', 'y'], categories=['a', 'b', 'z', 'd']),
         'D': [1, 2, 3, 4],
         'E': ['w', 'x', 'z', 'foo'],
         'F': [1.1, 2.2, 3.3, 4.4],
         'H': [True, False, False, False]
         }
    )

    # Test the transformation from dataframe to numpy ndarray and back again
    to_matrix = DataFrameToMatrix()
    matrix = to_matrix.fit_transform(test_df)
    matrix_test = to_matrix.transform(test_df)

    # These two matrices should be the same
    np_test_utils.assert_equal(matrix, matrix_test)

    # Test that the conversion gives us the same columns on a df with different category values
    matrix2 = to_matrix.transform(test_df2)
    assert matrix.shape == matrix2.shape

    # First two ROWS should be the same
    np_test_utils.assert_equal(matrix[0], matrix2[0])
    np_test_utils.assert_equal(matrix[1], matrix2[1])

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
