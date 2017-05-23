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
    'lease_time': datetime.timedelta(49710, 23000),
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

    import yara
    from brothon import dir_watcher
    ...

    def yara_match(file_path, rules):
        """Callback for a newly extracted file"""
        print('New Extracted File: {:s}'.format(file_path))
        print('Mathes:')
        pprint(rules.match(file_path))

    ...
        # Load/compile the yara rules
        my_rules = yara.compile(args.rule_index)

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

Risky Domains
-------------
The example will use the analysis in our `Risky Domains <https://github.com/Kitware/BroThon/blob/master/notebooks/Risky_Domains.ipynb>`_
notebook to flag domains that are 'at risk' and conduct a Virus Total query on those domains.
See brothon/examples/risky_dns.py for full code listing (code simplified below)

.. code-block:: python

    from brothon import bro_log_reader
    from brothon.utils import vt_query
    ...

        # Create a VirusTotal Query Class
        vtq = vt_query.VTQuery()

        # See our 'Risky Domains' Notebook for the analysis and
        # statistical methods used to compute this risky set of TLDs
        risky_tlds = set(['info', 'tk', 'xyz', 'online', 'club', 'ru', 'website', 'in', 'ws', 'top', 'site', 'work', 'biz', 'name', 'tech'])

        # Run the bro reader on the dns.log file looking for risky TLDs
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)
        for row in reader.readrows():

            # Pull out the TLD
            query = row['query']
            tld = tldextract.extract(query).suffix

            # Check if the TLD is in the risky group
            if tld in risky_tlds:
                # Make the query with the full query
                results = vtq.query_url(query)
                if results.get('positives'):
                    print('\nOMG the Network is on Fire!!!')
                    pprint(results)


**Example Output:**
To test this example simply do a "$ping uni10.tk" on a machine being monitored by your Bro IDS.

Note: You can also ping something like 'isaftaho.tk' which is not on any of the blacklist but will
still hit. The script will obviously cast a much wider net than just the blacklists.

::

  $ python risky_dns.py -f /usr/local/var/spool/bro/dns.log
    Successfully monitoring /usr/local/var/spool/bro/dns.log...

    OMG the Network is on Fire!!!
    {'filescan_id': None,
     'positives': 9,
     'query': 'uni10.tk',
     'scan_date': '2016-12-19 23:49:04',
     'scan_results': [('clean site', 55),
                      ('malicious site', 5),
                      ('unrated site', 4),
                      ('malware site', 4),
                      ('suspicious site', 1)],
     'total': 69,
     'url': 'http://uni10.tk/'}

Cert Checker
------------
There's been discussion about Let's Encrypt issuing certficates to possible phishing/malicious site owners. This example
will quickly check and dynamically monitor your Bro IDS x509 logs for certificates that may be from malicious sites.

See brothon/examples/cert_checker.py for full code listing (code simplified below)

.. code-block:: python

    from brothon import bro_log_reader
    from brothon.utils import vt_query
    ...

        # These domains may be spoofed with a certificate issued by 'Let's Encrypt'
        spoofed_domains = set(['paypal', 'gmail', 'google', 'apple','ebay', 'amazon'])

        # Run the bro reader on the x509.log file looking for spoofed domains
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)
        for row in reader.readrows():

            # Pull out the Certificate Issuer
            issuer = row['certificate.issuer']
            if "Let's Encrypt" in issuer:

                # Check if the certificate subject has any spoofed domains
                subject = row['certificate.subject']
                domain = subject[3:] # Just chopping off the 'CN=' part
                if any([domain in subject for domain in spoofed_domains]):
                    print('\n<<< Suspicious Certificate Found >>>')
                    pprint(row)

                    # Make a Virus Total query with the spoofed domain (just for fun)
                    results = vtq.query_url(domain)
                    if results.get('positives', 0) >= 2: # At least two hits
                        print('\n<<< Virus Total Query >>>')
                        pprint(results)


**Example Output:**
Simply run this example script on your Bro IDS x509.log.

::

  $ python cert_checker.py -f ../data/x509.log
    Successfully monitoring ../data/x509.log...

    <<< Suspicious Certificate Found >>>
    {'basic_constraints.ca': True,
     'certificate.issuer': "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
     'certificate.key_alg': 'rsaEncryption',
     'certificate.key_length': 4096,
     'certificate.key_type': 'rsa',
     'certificate.sig_alg': 'sha256WithRSAEncryption',
     'certificate.subject': 'CN=paypal.migems.com',
     ...}

    <<< Virus Total Query >>>
    {'filescan_id': None,
     'positives': 8,
     'query': 'paypal.migems.com',
     'scan_date': '2017-04-16 09:39:52',
     'scan_results': [('clean site', 50),
                      ('phishing site', 6),
                      ('unrated site', 6),
                      ('malware site', 1),
                      ('malicious site', 1)],
     'total': 64,
     'url': 'http://paypal.migems.com/'}



Simple Outlier Detector
-----------------------
Here's we demonstrating a TOY outlier detection to show the use of dataframe_cache
class and how we can stream data from Bro IDS into a dataframe
and run some simple statistics on that 'windowed' dataframe.

- Every 5 seconds we run the outlier detection
- The dataframe cache contains a window of data for the last 30 seconds

See brothon/examples/cert_checker.py for full code listing (code simplified below)

.. code-block:: python

    from brothon import bro_log_reader, live_simulator
    from brothon.analysis import dataframe_cache
    ...

        # Create a Bro IDS log reader
        print('Opening Data File: {:s}'.format(args.bro_log))
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)

        # Create a Dataframe Cache
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=30)  # 30 second cache

        # Add each new row into the cache
        time_delta = 5
        timer = time.time() + time_delta
        for row in reader.readrows():
            df_cache.add_row(row)

            # Every 5 seconds grab the dataframe from the cache
            if time.time() > timer:
                timer = time.time() + time_delta

                # Get the windowed dataframe (30 second window)
                my_df = df_cache.dataframe()

                # Add query length and entropy
                my_df['query_length'] = my_df['query'].str.len()
                my_df['query_entropy'] = my_df['query'].apply(lambda x: entropy(x))

                # Print out the range of the daterange and some stats
                print('DataFrame TimeRange: {:s} --> {:s}'.format(str(my_df['ts'].min()), str(my_df['ts'].max())))

                # Compute Outliers
                # Note: This is a TOY example, assuming a guassian distribution which it isn't, etc..
                my_outliers = my_df[outliers(my_df['query_length'])]
                if not my_outliers.empty:
                    print('<<< Outliers Detected! >>>')
                    print(my_outliers[['query','query_length', 'query_entropy']])


**Example Output:**
Run this example script on your Bro IDS dns.log. Here we ran the outlier script
and then we did a $ ping <very long hostname> a couple of times. We
can see that those dns queries show up as Outliers.

::

    $ python simple_dns_outlier.py -f /usr/local/var/spool/bro/dns.log
    Opening Data File: /usr/local/var/spool/bro/dns.log
    Successfully monitoring /usr/local/var/spool/bro/dns.log...
    DataFrame TimeRange: 2017-05-23 16:43:12.155247 --> 2017-05-23 16:43:57.201749
    DataFrame TimeRange: 2017-05-23 16:43:27.734151 --> 2017-05-23 16:44:02.696416
    DataFrame TimeRange: 2017-05-23 16:43:32.226345 --> 2017-05-23 16:44:02.696416
    DataFrame TimeRange: 2017-05-23 16:43:32.226345 --> 2017-05-23 16:44:18.608977
    <<< Outliers Detected! >>>
                                                   query  query_length  query_entropy
    0  abcxxyzifaoijpoqjefpqrgqhergphqeprghqperhgpqhe...            68       3.797085
    8  xyaabcxxyzifaoijpoqjefpqrgqhergphqeprghqperhgp...            71       3.850374
