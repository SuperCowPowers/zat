BroThon |travis| |Coverage Status| |supported-versions| |license|
================================================================================================================

**Bro + Python = BroThon!**

The BroThon package supports the ingestion, processing, and analysis of Bro IDS data with Python.

|kitware-logo|

Why
---
Bro IDS already has a flexible, powerful scripting language why should I use BroThon?

**Offloading:** Running more complex tasks (yara sigs on files, state machines, ML models, etc..) should
be offloaded from Bro IDS so that Bro can focus on the efficient processing of high volume network traffic.

**Python:** Pulling Bro data into Python allows us to leverage a large set of data analysis, statistics,
machine learning and visualization options.

Example Uses
------------
- Easy ingestion of Bro Logs into Python (including logs that are actively being written to)
- Bro Logs to Pandas Dataframes (and then dataframes to Machine Learning :)
- Dynamically monitor files.log and make VirusTotal Queries
- Dynamically monitor http.log and show 'uncommon' User Agents
- Running Yara Signatures on Extracted Files
- See `BroThon Examples <https://brothon.readthedocs.io/en/latest/examples.html>`__ for more details.


Install
-------

::

    $ pip install brothon


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
