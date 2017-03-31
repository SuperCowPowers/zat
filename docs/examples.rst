========
Examples
========

To use Bro Python Utilities in a project::

	import brothon

Example 1
---------
See brothon/examples/bro_log_pprint.py for full code listing.

.. code-block:: python

	from pprint import pprint
	from brothon import bro_log_reader
	...
		# Run the bro reader on a given log file
		reader = bro_log_reader.BroLogReader('dhcp.log')
		for row in reader.readrows():
			pprint(row)


Example Output
~~~~~~~~~~~~~~
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

Example Output
~~~~~~~~~~~~~~

::

				host      id.orig_h  id.orig_p  response_body_len status_code             uri
	chopraresidency.com  192.168.84.10       1030                372         200         /foo.js
	blogs.redheberg.com  192.168.84.10       1031               2111         200     /mltools.js
		santiyesefi.com  192.168.84.10       1034                327         404     /mltools.js
		tudespacho.net  192.168.84.10       1033              12350         200  /32002245.html
		tudespacho.net  192.168.84.10       1033               5176         200      /98765.pdf
	...
