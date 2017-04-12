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


**Example Output:** You get back a nice Python Dictionary with timestamps and types properly converted.

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


Creating a Pandas DataFrame
---------------------------
See brothon/examples/bro_log_pandas.py for full code listing. Notice that it's one line of code to convert to a Pandas DataFrame.

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


Bro Files Log to VirusTotal Query
---------------------------------
See brothon/examples/file_log_vtquery.py for full code listing (code simplified below)

.. code-block:: python

    from brothon import bro_log_reader
    from brothon.utils import vt_query
    ...
        # Run the bro reader on on the files.log output
        reader = bro_log_reader.BroLogReader('files.log', tail=True) # This will dynamically monitor this Bro log
        for row in reader.readrows():

            # Make the query with the file sha
            pprint(vtq.query(row['sha256']))


**Example Output:** Each file sha256/sha1 is queried against the VirusTotal Service.

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

Bro HTTP Log User Agents
------------------------
See brothon/examples/http_user_agents.py for full code listing (code simplified below)

.. code-block:: python

    from collections import Counter
    from brothon import bro_log_reader
    ...
        # Run the bro reader on a given log file counting up user agents
        http_agents = Counter()
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)
        for count, row in enumerate(reader.readrows()):
            # Track count
            http_agents[row['user_agent']] += 1

        print('\nLeast Common User Agents:')
        pprint(http_agents.most_common()[:-50:-1])


**Example Output:** Might be some interesting agents on this list...

::

    Least Common User Agents:
    [
     ('NetSupport Manager/1.0', 1),
     ('Mozilla/4.0 (Windows XP 5.1) Java/1.6.0_23', 1),
     ('Mozilla/5.0 (X11; Linux i686 on x86_64; rv:10.0.2) Gecko/20100101 Firefox/10.0.2', 1),
     ('oh sure', 2),
     ('Fastream NETFile Server', 2),
     ('Mozilla/5.0 (X11; Linux i686; rv:2.0.1) Gecko/20100101 Firefox/4.0.1', 3),
     ('Mozilla/5.0 (Windows NT 6.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1', 4),
     ('NESSUS::SOAP', 5),
     ('webmin', 6),
     ('Nessus SOAP v0.0.1 (Nessus.org)', 10),
     ('Mozilla/4.0 (compatible; gallery_203.nasl; Googlebot)', 31),
     ("mercuryboard_user_agent_sql_injection.nasl'", 31),
     ('Mozilla/5.0 (X11; Linux i686; rv:10.0.2) Gecko/20100101 Firefox/10.0.2', 46),
     ('*/*', 49),
     ('Nessus', 52),
     ...
     ('Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)', 6166),


Yara rules on Bro extracted files
---------------------------------
The example will dymancially monitor the extract_files directory and when a file is
dropped by Bro IDS the code will run a set of Yara rules against that file.
See brothon/examples/yara_matches.py for full code listing (code simplified below)

.. code-block:: python

    from brothon import yara_rules, dir_watcher
    ...

    def yara_match(file_path, rules):
        """Callback for a newly extracted file"""
        print('New Extracted File: {:s}'.format(file_path))
        print('Mathes:')
        pprint(rules.match(file_path))

    ...
        # Create a Yara Rules Class
        print('Loading Yara Rules from {:s}'.format(args.rule_index))
        my_rules = yara_rules.YaraRules(rule_index=args.rule_index)

        # Create DirWatcher and start watching the Bro extract_files directory
        print('Watching Extract Files Directory: {:s}'.format(args.extract_dir))
        dir_watcher.DirWatcher(args.extract_dir, callback=yara_match, rules=my_rules)


**Example Output:**

::

    Loading Yara Rules from ../brothon/utils/yara_test/index.yar
    Watching Extract Files Directory: /home/ubuntu/software/bro/extract_files
    New Extracted File: /home/ubuntu/software/bro/extract_files/test.tmp
    Mathes:
    [AURIGA_driver_APT1]

