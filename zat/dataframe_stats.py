""" DataFrame Statistics Methods
        - Contingency Table (also called Cross Tabulation)
        - Joint Distribution
        - G-Scores
    References:
        - http://en.wikipedia.org/wiki/Contingency_table
        - http://en.wikipedia.org/wiki/G_test (Wikipedia)
        - http://udel.edu/~mcdonald/stathyptesting.html (Hypothesis Testing)
"""
from __future__ import print_function
import math

# Third Party
import pandas as pd


def contingency_table(dataframe, rownames, colnames, margins=True):
    """Contingency Table (also called Cross Tabulation)
       - Table in a matrix format that displays the (multivariate) frequency distribution of the variables
       - http://en.wikipedia.org/wiki/Contingency_table
       Args:
           rownames: the column name or list of columns names that make the keys of the rows
           colnames: the column name or list of columns names that make the keys of the columns
    """
    # Taking just the rownames + colnames of the dataframe
    sub_set = [rownames, colnames]
    _sub_df = dataframe[sub_set]
    return _sub_df.pivot_table(index=rownames, columns=colnames, margins=margins, aggfunc=len, fill_value=0)


def joint_distribution(dataframe, rownames, colnames):
    """Joint Distribution Table
       - The Continguency Table normalized by the total number of observations
       Args:
           rownames: the column name or list of columns names that make the keys of the rows
           colnames: the column name or list of columns names that make the keys of the columns
    """
    cont_table = contingency_table(dataframe, rownames=rownames, colnames=colnames, margins=True)
    total_observations = cont_table['All']['All']
    return cont_table/total_observations


def expected_counts(dataframe, rownames, colnames):
    """Expected counts of the multivariate frequency distribution of the variables given the
       null hypothesis of complete independence between variables.
       Args:
           rownames: the column name or list of columns names that make the keys of the rows
           colnames: the column name or list of columns names that make the keys of the columns
    """
    cont_table = contingency_table(dataframe, rownames=rownames, colnames=colnames, margins=True)
    row_counts = cont_table['All']
    column_counts = cont_table.loc['All']
    total_observations = cont_table['All']['All']

    # There didn't seem to be a good way to vectorize this (Fixme?)
    for column in cont_table.columns:
        for row in cont_table.index:
            cont_table[column][row] = column_counts[column]*row_counts[row]/total_observations
    return cont_table


def g_test_scores(dataframe, rownames, colnames):
    """G Test Score for log likelihood ratio
       - http://en.wikipedia.org/wiki/G_test (Wikipedia)
       - 95th percentile; 5% level; p < 0.05; critical value = 3.84
       - 99th percentile; 1% level; p < 0.01; critical value = 6.63
       - 99.9th percentile; 0.1% level; p < 0.001; critical value = 10.83
       - 99.99th percentile; 0.01% level; p < 0.0001; critical value = 15.13

       Args:
           rownames: the column name or list of columns names that make the keys of the rows
           colnames: the column name or list of columns names that make the keys of the columns
    """
    cont_table = contingency_table(dataframe, rownames=rownames, colnames=colnames, margins=False)
    exp_counts = expected_counts(dataframe, rownames=rownames, colnames=colnames)

    # There didn't seem to be a good way to vectorize this (Fixme?)
    for row in cont_table.index:
        g_score = 0
        for column in cont_table.columns:
            g_score += compute_g(cont_table[column][row], exp_counts[column][row])
        for column in cont_table.columns:
            cont_table[column][row] = g_score if cont_table[column][row] > exp_counts[column][row] else -g_score
    return cont_table


def compute_g(count, expected):
    """G Test Score for log likelihood ratio
       - http://en.wikipedia.org/wiki/G_test (Wikipedia)
    """
    try:
        return 2.0 * count * math.log(count/expected)
    except ValueError:
        return 0


# Simple test of the functionality
def test():
    """Test for DataFrame Stats module"""

    import os
    from zat.utils import file_utils

    # Open a dataset (relative path)
    data_dir = file_utils.relative_dir(__file__, 'test_data')
    file_path = os.path.join(data_dir, 'g_test_data.csv')
    dataframe = pd.read_csv(file_path)
    print(dataframe.head())

    # Print out the contingency_table
    print('\nContingency Table')
    print(contingency_table(dataframe, 'name', 'status'))

    # Print out the joint_distribution
    print('\nJoint Distribution Table')
    print(joint_distribution(dataframe, 'name', 'status'))

    # Print out the expected_counts
    print('\nExpected Counts Table')
    print(expected_counts(dataframe, 'name', 'status'))

    # Print out the g_test scores
    print('\nG-Test Scores')
    print(g_test_scores(dataframe, 'name', 'status'))


if __name__ == "__main__":
    test()
