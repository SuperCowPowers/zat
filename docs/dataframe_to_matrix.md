# Dataframe to Matrix (ndarray)

This documents discusses some of the design decisions made when implementing the new DataFrameToMatrix class.

- **Train/Predict Column Order:** The most important aspect of this class is that it must produce consistently ordered output between training and prediction. In particular one-hot encoding for categorical fields must keep an ordered list of categorical values that are captured during training  (fit/fit-transform) and then used during prediction (transform). SCP Labs has a great notebook describing this issue in detail [Categorical Encoding Dangers](https://nbviewer.jupyter.org/github/SuperCowPowers/scp-labs/blob/main/notebooks/Categorical_Encoding_Dangers.ipynb)

- **NaN Handling**: In general Pandas Dataframes are great about handling NaN values in a general and robust way. The same is NOT true of Scikit-Learn (see [Scikit No NaNs](https://stackoverflow.com/questions/30317119/classifiers-in-scikit-learn-that-handle-nan-null) and [Handling Missing Data](https://machinelearningmastery.com/handle-missing-data-python/)). So NaNs must be detected and handled accordingly. Specifically we propose this logic:
  - **Categorical NaNs:** The NaNs will become another category value, this simply adds 1 column to the one-hot encoding matrix and provides the handling of NaNs in a meaningful and robust way.
  - **Numerical NaNs:** Both integer and float columns with NaNs in them will have a 'nan_replace' value that can be passed into the class. The parameter will be a dictionary with columns as keys and the replacements as the values.

- **Normalization:** The class will provide automatic normalization of numeric columns.
- **Category Detection:** The class will provide automatic Category Detection for columns of type 'object'.
- **Standardize on np.float32 output:** The ndarray that is produced has to be 'single typed' by definition, so we're thinking of having this be np.float32 by default. This default could be overwritten with the 'output_dtype' option. **Note:** The dimensionality explosion from one-hot encoding is driving this default decision. Storing a bunch 0 and 1 as np.float64 just feels bloated and wasteful.

### References

- [Categorical Encoding Dangers](https://nbviewer.jupyter.org/github/SuperCowPowers/scp-labs/blob/main/notebooks/Categorical_Encoding_Dangers.ipynb)
- [Numpy NDarray](https://docs.scipy.org/doc/numpy/reference/arrays.ndarray.html)
- [Scikit-Learn No NaNs](https://stackoverflow.com/questions/30317119/classifiers-in-scikit-learn-that-handle-nan-null)
- [Handling Missing Data](https://machinelearningmastery.com/handle-missing-data-python/)