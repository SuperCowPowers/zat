## Bro Analysis Tools (BAT) [![travis](https://travis-ci.org/SuperCowPowers/bat.svg?branch=master)](https://travis-ci.org/SuperCowPowers/bat) [![Coverage Status](https://coveralls.io/repos/github/SuperCowPowers/bat/badge.svg?branch=master)](https://coveralls.io/github/SuperCowPowers/bat?branch=master) [![supported-versions](https://img.shields.io/pypi/pyversions/bat.svg)](https://pypi.python.org/pypi/bat) [![license](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://choosealicense.com/licenses/apache-2.0)


The BAT Python package supports the processing and analysis of Bro data
with Pandas, scikit-learn, and Spark

### Recent: Large Log to Dataframe Improvements
See our recent work on improving Pandas dataframes from large log files: [Large Dataframes](docs/large_dataframes.md)

## BroCon 2017 Presentation

Data Analysis, Machine Learning, Bro, and You!
([Video](https://www.youtube.com/watch?v=pG5lU9CLnIU))

## Why BAT?

Bro already has a flexible, powerful scripting language why should I use
BAT?

**Offloading:** Running complex tasks like statistics, state machines,
machine learning, etc.. should be offloaded from Bro so that Bro can
focus on the efficient processing of high volume network traffic.

**Data Analysis:** We have a large set of support classes that help
bridge from raw Bro data to packages like Pandas, scikit-learn, and
Spark. We also have example notebooks that show step-by-step how to get
from here to there.


### Getting Started
- [Examples of Using BAT](docs/examples.md)

### How-To Analysis Notebooks

- [Bro to Scikit-Learn] (https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Bro_to_Scikit_Learn.ipynb)
- [Bro to Matplotlib] (https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Bro_to_Plot.ipynb)
- [Bro to Parquet to Spark] (https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Bro_to_Parquet_to_Spark.ipynb)
- [Bro to Kafka to Spark] (https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Bro_to_Kafka_to_Spark.ipynb)
- [Clustering: Picking K (or not)] (https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Clustering_Picking_K.ipynb)
- [Anomaly Detection Exploration] (https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Anomaly_Detection.ipynb)
- [Risky Domains Stats and Deployment](https://nbviewer.jupyter.org/github/SuperCowPowers/bat/blob/master/notebooks/Risky_Domains.ipynb)

Install
-------

    $ pip install bat

Documentation
-------------

<https://supercowpowers.github.io/bat/>

Thanks
------

-   The DummyEncoder is based on Tom Augspurger's great PyData Chicago
    2016 [Talk](https://youtu.be/KLPtEBokqQ0)

