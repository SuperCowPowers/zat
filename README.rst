BroThon |travis| |Coverage Status| |supported-versions| |license|
================================================================================================================

**Bro + Python = BroThon!**

The BroThon package supports the ingestion, processing, and analysis of Bro IDS data with Python.

|kitware-logo|

Why BroThon?
------------
Bro IDS already has a flexible, powerful scripting language why should I use BroThon?

**Offloading:** Running more complex tasks (yara sigs on files, state machines, machine learning, etc..) should
be offloaded from Bro IDS so that Bro can focus on the efficient processing of high volume network traffic.

**Python:** Pulling Bro data into Python allows us to leverage a large set of of Python modules for data analysis,
statistics, machine learning and visualization options.

**Data Analysis:** A growing set of notebooks/examples using statistics and machine learning on Bro data.

Easy to Use
-----------

.. code-block:: python

    from brothon import bro_log_reader
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
    'lease_time': 4294967000.0,
    'mac': '00:20:18:eb:ca:54',
    'trans_id': 495764278,
    'ts': datetime.datetime(2012, 7, 20, 3, 14, 12, 219654),
    'uid': 'CJsdG95nCNF1RXuN5'}
    ...

More Examples
-------------
- Easy ingestion of any Bro Log into Python (dynamic tailing and log rotations are handled)
- Bro Logs to Pandas Dataframes (and then dataframes to Machine Learning :)
- Dynamically monitor files.log and make VirusTotal Queries
- Dynamically monitor http.log and show 'uncommon' User Agents
- Running Yara Signatures on Extracted Files
- See `BroThon Examples <https://brothon.readthedocs.io/en/latest/examples.html>`__ for more details.

Analysis Notebooks
------------------
BroThon enables the processing, analysis, and machine learning of realtime data coming from Bro IDS.

- Risky Domains Stats and Deployment: `Risky Domains <https://github.com/Kitware/BroThon/blob/master/notebooks/Risky_Domains.ipynb>`__

Install
-------

::

    $ pip install brothon
    or
    $ pip install brothon[all]   # Includes additional dependencies to run all examples (yara, etc)


Documentation
-------------

`BroThon.readthedocs.org <https://BroThon.readthedocs.org/>`__


.. |kitware-logo| image:: https://www.kitware.com/img/small_logo_over.png
   :target: https://www.kitware.com
   :alt: Kitware Logo
.. |travis| image:: https://img.shields.io/travis/Kitware/BroThon.svg
   :target: https://travis-ci.org/Kitware/BroThon
.. |Coverage Status| image:: https://coveralls.io/repos/github/Kitware/BroThon/badge.svg?branch=master
   :target: https://coveralls.io/github/Kitware/BroThon?branch=master
.. |version| image:: https://img.shields.io/pypi/v/BroThon.svg
   :target: https://pypi.python.org/pypi/BroThon
.. |wheel| image:: https://img.shields.io/pypi/wheel/BroThon.svg
   :target: https://pypi.python.org/pypi/BroThon
.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/BroThon.svg
   :target: https://pypi.python.org/pypi/BroThon
.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/BroThon.svg
   :target: https://pypi.python.org/pypi/BroThon
.. |license| image:: https://img.shields.io/badge/License-Apache%202.0-green.svg
   :target: https://choosealicense.com/licenses/apache-2.0
