"""The DummyEncoder Class is based on Tom Augspurger's great PyData
   Chicago 2016 Talk <https://youtu.be/KLPtEBokqQ0>.
   The original code can be found at git@github.com:TomAugspurger/mtg.git"""
from __future__ import print_function
import numpy as np
import pandas as pd
from sklearn.pipeline import TransformerMixin


class DummyEncoder(TransformerMixin):
    """The DummyEncoder Class converts DataFrame to numpy ndarray (matrix).
       Categorical columns are properly dummy encoded (one hot) to column bit vectors"""

    def __init__(self):
        """Initialize the DummyEncoder class"""
        self.index_ = None
        self.columns_ = None
        self.cat_columns_ = None
        self.non_cat_columns_ = None
        self.cat_map_ = None
        self.cat_blocks_ = None
        self.columns_in_order = None

    def fit_transform(self, df):
        """Fit method for the DummyEncoder"""
        self.index_ = df.index
        self.columns_ = df.columns
        self.cat_columns_ = df.select_dtypes(include=['category']).columns
        self.non_cat_columns_ = df.columns.drop(self.cat_columns_)
        self.cat_map_ = {col: df[col].cat for col in self.cat_columns_}

        # Store all the information about categories/values so we can 'back map' later
        left = len(self.non_cat_columns_)
        self.cat_blocks_ = {}
        for col in self.cat_columns_:
            right = left + len(df[col].cat.categories)
            self.cat_blocks_[col], left = slice(left, right), right

        # This is to ensure that transform always produces the same columns in the same order
        df_with_dummies = pd.get_dummies(df)
        self.columns_in_order = df_with_dummies.columns.tolist()

        # Return the numpy matrix
        return np.asarray(df_with_dummies)

    def transform(self, df):
        """Transform dataframe into a numpy ndarray(matrix)"""

        # Make sure the dataframe columns are the same as the ones passed to fit
        assert df.columns.equals(self.columns_)

        # Convert the dataframe with get_dummies
        df_with_dummies = pd.get_dummies(df)

        # Make sure our columns exactly match what we stored during the fit operation
        my_columns = set(df_with_dummies.columns.tolist())
        output_column_set = set(self.columns_in_order)
        for column in my_columns.difference(output_column_set):
            print('Deleting extra column {:s}'.format(column))
            del df_with_dummies[column]
        for column in output_column_set.difference(my_columns):
            print('Adding column {:s}'.format(column))
            df_with_dummies[column] = 0

        # Returns the same columns in the same order every time
        return np.asarray(df_with_dummies[self.columns_in_order])

    def inverse_transform(self, X):
        """Inverse Transform: numpy ndarray(matrix) to dataframe with original columns"""
        non_cat = pd.DataFrame(X[:, :len(self.non_cat_columns_)],
                               columns=self.non_cat_columns_)
        cats = []
        for col, cat in self.cat_map_.items():
            slice_ = self.cat_blocks_[col]
            codes = X[:, slice_].argmax(1)
            series = pd.Series(pd.Categorical.from_codes(
                codes, cat.categories, ordered=cat.ordered
            ), name=col)
            cats.append(series)
        df = pd.concat([non_cat] + cats, axis=1)[self.columns_]
        return df


# Simple test of the functionality
def test():
    """Test for DummyEncoder Class"""
    import pandas.util.testing as test_utils
    import numpy.testing as numpy_test_utils

    test_df = pd.DataFrame(
        {'A': pd.Categorical(['a', 'b', 'c', 'a'], ordered=True),
         'B': pd.Categorical(['a', 'b', 'c', 'a'], ordered=False),
         'C': pd.Categorical(['a', 'b', 'z', 'a'], categories=['a', 'b', 'z', 'd']),
         'D': [1, 2, 3, 4],
         }
    )
    test_df2 = pd.DataFrame(
        {'A': pd.Categorical(['a', 'b', 'b', 'a'], ordered=True),
         'B': pd.Categorical(['a', 'b', 'd', 'a'], ordered=False),
         'C': pd.Categorical(['a', 'b', 'z', 'y'], categories=['a', 'b', 'z', 'd']),
         'D': [1, 2, 3, 4],
         }
    )

    # Test the transformation from dataframe to numpy ndarray and back again
    encoder = DummyEncoder()
    transformed_data = encoder.fit_transform(test_df)
    back_to_original = encoder.inverse_transform(transformed_data)
    test_utils.assert_frame_equal(back_to_original, test_df)

    # Test that the encoder gives us the same columns on a df with different category values
    transformed_data2 = encoder.transform(test_df2)
    assert transformed_data.shape == transformed_data2.shape

    # First two ROWS should be the same
    numpy_test_utils.assert_equal(transformed_data[0], transformed_data2[0])
    numpy_test_utils.assert_equal(transformed_data[1], transformed_data2[1])


if __name__ == "__main__":
    test()
