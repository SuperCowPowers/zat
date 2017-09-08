Bro Analysis Tools (BAT) |travis| |Coverage Status| |supported-versions| |license|
================================================================================================================

**Bro Analysis Tools**

The BAT Python package supports the processing and analysis of Bro IDS data with Pandas, scikit-learn, and Spark


Why BAT?
--------
Bro IDS already has a flexible, powerful scripting language why should I use BAT?

**Offloading:** Running complex tasks like statistics, state machines, machine learning, etc.. should
be offloaded from Bro IDS so that Bro can focus on the efficient processing of high volume network traffic.

**Data Analysis:** We have a large set of support classes that help bridge from raw Bro IDS data to packages
like Pandas, scikit-learn, and Spark. We also have example notebooks that show step-by-step how to get
from here to there.

Example: Pull in Bro Logs as Python Dictionaries
------------------------------------------------

.. code-block:: python

    from bat import bro_log_reader
    ...
        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader('dhcp.log')
        for row in reader.readrows():
            pprint(row)


**Output:** Each row is a nice Python Dictionary with timestamps and types properly converted.

::

    {'assigned_ip': '192.168.84.10',
    'id.orig_h': '192.168.84.10',
    'id.orig_p': 68,
    'id.resp_h': '192.168.84.1',
    'id.resp_p': 67,
    'lease_time': datetime.timedelta(49710, 23000),
    'mac': '00:20:18:eb:ca:54',
    'trans_id': 495764278,
    'ts': datetime.datetime(2012, 7, 20, 3, 14, 12, 219654),
    'uid': 'CJsdG95nCNF1RXuN5'}
    ...

Example: Bro log to Pandas DataFrame (in one line of code)
----------------------------------------------------------
.. code-block:: python

    from bat.log_to_dataframe import LogToDataFrame
    ...
        # Create a Pandas dataframe from a Bro log
        bro_df = LogToDataFrame('/path/to/dns.log')

        # Print out the head of the dataframe
        print(bro_df.head())


**Output:** All the Bro log data is in a Pandas DataFrame with proper types and timestamp as the index

::

                                                         query      id.orig_h  id.orig_p id.resp_h \
    ts
    2013-09-15 17:44:27.631940                     guyspy.com  192.168.33.10       1030   4.2.2.3
    2013-09-15 17:44:27.696869                 www.guyspy.com  192.168.33.10       1030   4.2.2.3
    2013-09-15 17:44:28.060639   devrubn8mli40.cloudfront.net  192.168.33.10       1030   4.2.2.3
    2013-09-15 17:44:28.141795  d31qbv1cthcecs.cloudfront.net  192.168.33.10       1030   4.2.2.3
    2013-09-15 17:44:28.422704                crl.entrust.net  192.168.33.10       1030   4.2.2.3


More Examples
-------------
- Easy ingestion of any Bro Log into Python (dynamic tailing and log rotations are handled)
- Bro Logs to Pandas Dataframes and Scikit-Learn
- Dynamically monitor files.log and make VirusTotal Queries
- Dynamically monitor http.log and show 'uncommon' User Agents
- Running Yara Signatures on Extracted Files
- Checking x509 Certificates
- Anomaly Detection
- See `BAT Examples <https://bat-tools.readthedocs.io/en/latest/examples.html>`__ for more details.

Analysis Notebooks
------------------
BAT enables the processing, analysis, and machine learning of realtime data coming from Bro IDS.

- Risky Domains Stats and Deployment: `Risky Domains <https://github.com/Kitware/bat/blob/master/notebooks/Risky_Domains.ipynb>`__
- Bro to Scikit-Learn: `Bro to Scikit <https://github.com/Kitware/bat/blob/master/notebooks/Bro_to_Scikit_Learn.ipynb>`__
- Bro to Matplotlib: `Bro to Plot <https://github.com/Kitware/bat/blob/master/notebooks/Bro_to_Plot.ipynb>`__
- Bro to Spark: `Bro to Spark <https://github.com/Kitware/bat/blob/master/notebooks/Bro_to_Spark.ipynb>`__
- Bro to Parquet to Spark: `Bro to Parquet to Spark <https://github.com/Kitware/bat/blob/master/notebooks/Bro_to_Parquet_to_Spark.ipynb>`__
- Clustering: Picking K (or not): `Clustering K Hyperparameter <https://github.com/Kitware/bat/blob/master/notebooks/Clustering_Picking_K.ipynb>`__
- Anomaly Detection Exploration: `Anomaly Detection <https://github.com/Kitware/bat/blob/master/notebooks/Anomaly_Detection.ipynb>`__

Install
-------

::

    $ pip install bat


Documentation
-------------

`bat-tools.readthedocs.org <https://bat-tools.readthedocs.org/>`__


Thanks
------
- The DummyEncoder is based on Tom Augspurger's great PyData Chicago 2016 `Talk <https://youtu.be/KLPtEBokqQ0>`__

|kitware-logo|

.. |kitware-logo| image:: https://www.kitware.com/img/small_logo_over.png
   :target: https://www.kitware.com
   :alt: Kitware Logo
.. |travis| image:: https://img.shields.io/travis/Kitware/bat.svg
   :target: https://travis-ci.org/Kitware/bat
.. |Coverage Status| image:: https://coveralls.io/repos/github/Kitware/bat/badge.svg?branch=master
   :target: https://coveralls.io/github/Kitware/bat?branch=master
.. |version| image:: https://img.shields.io/pypi/v/bat.svg
   :target: https://pypi.python.org/pypi/bat
.. |wheel| image:: https://img.shields.io/pypi/wheel/bat.svg
   :target: https://pypi.python.org/pypi/bat
.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/bat.svg
   :target: https://pypi.python.org/pypi/bat
.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/bat.svg
   :target: https://pypi.python.org/pypi/bat
.. |license| image:: https://img.shields.io/badge/License-Apache%202.0-green.svg
   :target: https://choosealicense.com/licenses/apache-2.0
