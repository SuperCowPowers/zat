"""Silly data generator (Faker (https://github.com/joke2k/faker) and others
   are much better, but we just need something simple"""
from __future__ import print_function
import string

# Third Party
import pandas as pd
import numpy as np


def df_random(num_numeric=3, num_categorical=3, num_rows=100):
    """Generate a dataframe with random data. This is a general method
       to easily generate a random dataframe, for more control of the
       random 'distributions' use the column methods (df_numeric_column, df_categorical_column)
       For other distributions you can use numpy methods directly (see example at bottom of this file)
        Args:
            num_numeric (int): The number of numeric columns (default = 3)
            num_categorical (int): The number of categorical columns (default = 3)
            num_rows (int): The number of rows to generate  (default = 100)
    """

    # Construct DataFrame
    df = pd.DataFrame()
    column_names = string.ascii_lowercase

    # Create numeric columns
    for name in column_names[:num_numeric]:
        df[name] = df_numeric_column(num_rows=num_rows)

    # Create categorical columns
    for name in column_names[num_numeric:num_numeric+num_categorical]:
        df[name] = df_categorical_column(['foo', 'bar', 'baz'], num_rows=num_rows)

    # Return the dataframe
    return df


def df_numeric_column(min_value=0, max_value=1, num_rows=100):
    """Generate a numeric column with random data
        Args:
            min_value (float): Minimum value (default = 0)
            max_value (float): Maximum value (default = 1)
            num_rows (int): The number of rows to generate  (default = 100)
    """
    # Generate numeric column
    return pd.Series(np.random.uniform(min_value, max_value, num_rows))


def df_categorical_column(category_values, num_rows=100, probabilities=None):
    """Generate a categorical column with random data
        Args:
            category_values (list): A list of category values (e.g. ['red', 'blue', 'green'])
            num_rows (int): The number of rows to generate  (default = 100)
            probabilities (list): A list of probabilities of each value (e.g. [0.6, 0.2, 0.2]) (default=None  an equal probability)
    """
    splitter = np.random.choice(range(len(category_values)), num_rows, p=probabilities)
    return pd.Series(pd.Categorical.from_codes(splitter, categories=category_values))


def test():
    """Test the data generator methods"""
    df = df_random()
    print('Random DataFrame')
    print(df.head())

    # Test the numerical column generator
    df['delta_v'] = df_numeric_column(-100, 100)
    print('\nNumerical column generator (added delta_v)')
    print(df.head())

    # Test the categorical column generator
    df['color'] = df_categorical_column(['red', 'green', 'blue'])
    print('\nCategorical column generator (added color)')
    print(df.head())

    # Test the categorical column generator with probabilities
    df['color'] = df_categorical_column(['red', 'green', 'blue'], probabilities=[0.6, 0.3, 0.1])
    print('\nProbabilities should be ~60% red, %30 green and %10 blue')
    print(df['color'].value_counts())

    # Also we can just use the built in Numpy method for detailed control
    # over the numeric distribution
    my_series = pd.Series(np.random.normal(0, 1, 1000))
    print('\nStats on numpy normal (gaussian) distribution')
    print(my_series.describe())


if __name__ == '__main__':
    test()
