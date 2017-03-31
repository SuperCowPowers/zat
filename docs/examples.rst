========
Examples
========

To use Bro Python Utilities in a project::

    import brothon

BroLog to Python
----------------
See brothon/examples/bro_log_pprint.py for full code listing.

.. code-block:: python

    from pprint import pprint
    from brothon import bro_log_reader
    ...
        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader('dhcp.log')
        for row in reader.readrows():
            pprint(row)


**Example Output**
You get back a nice Python Dictionary with timestamps and types properly converted.

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

Creating a Pandas DataFrame!
----------------------------
See brothon/examples/bro_log_pandas.py for full code listing. Notice that it's one line of code to convert to a Pandas DataFrame!

.. code-block:: python

    import pandas as pd
    from brothon import bro_log_reader
    ...

        # Create a bro reader on a given log file
        reader = bro_log_reader.BroLogReader('http.log')

        # Create a Pandas dataframe from reader
        bro_df = pd.DataFrame(reader.readrows())

        # Print out the head of the dataframe
        print(bro_df.head())

**Example Output**

::

                   host      id.orig_h  id.orig_p  response_body_len status_code             uri
     hopraresidency.com  192.168.84.10       1030                372         200         /foo.js
    blogs.redheberg.com  192.168.84.10       1031               2111         200     /mltools.js
        santiyesefi.com  192.168.84.10       1034                327         404     /mltools.js
         tudespacho.net  192.168.84.10       1033              12350         200  /32002245.html
         tudespacho.net  192.168.84.10       1033               5176         200      /98765.pdf
...


Bro Files Log to VirusTotal Query
---------------------------------
See brothon/examples/bro_log_vtquery.py for full code listing (code simplified below)

.. code-block:: python

    from brothon import bro_log_reader
    from brothon.utils import vt_query
    ...
        # Run the bro reader on on the files.log output
        reader = bro_log_reader.BroLogReader('files.log', tail=True) # This will dynamically monitor this Bro log
        for row in reader.readrows():

            # Make the query with the file sha
            pprint(vtq.query(row['sha256']))


**Example Output**
Each file sha256/sha1 is queried against the VirusTotal Service.

::


    {'file_sha': 'bdf941b7be6ba2a7a58b0aef9471342f8677b31c', 'not_found': True}
    {'file_sha': '2283efe050a0a99e9a25ea9a12d6cf67d0efedfd', 'not_found': True}
    {'file_sha': 'c73d93459563c1ade1f1d39fde2efb003a82ca4b',
        u'positives': 42,
        u'scan_date': u'2015-09-17 04:38:23',
        'scan_results': [(u'Gen:Variant.Symmi.205', 6),
            (u'Trojan.Win32.Generic!BT', 2),
            (u'Riskware ( 0015e4f01 )', 2),
            (u'Trojan.Inject', 2),
            (u'PAK_Generic.005', 2)]}

    {'file_sha': '15728b433a058cce535557c9513de196d0cd7264',
        u'positives': 33,
        u'scan_date': u'2015-09-17 04:38:21',
        'scan_results': [(u'Java.Exploit.CVE-2012-1723.Gen.A', 6),
            (u'LooksLike.Java.CVE-2012-1723.a (v)', 2),
            (u'Trojan-Downloader ( 04c574821 )', 2),
            (u'Exploit:Java/CVE-2012-1723', 1),
            (u'UnclassifiedMalware', 1)]}
