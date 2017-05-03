"""Risky DNS BroThon Example"""
from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Third Party Imports
try:
    import tldextract
except ImportError:
    print('\nThis example needs tldextract. Please do a $pip install tldextract and rerun this example')
    sys.exit(1)

# Local imports
from brothon import bro_log_reader
from brothon.utils import vt_query

if __name__ == '__main__':
    # Example to run the bro log reader on a given file

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--bro-log', type=str, help='Specify a bro log to run BroLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # If no args just call help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Sanity check that this is a dns log
    if not args.bro_log.endswith('dns.log'):
        print('This example only works with Bro dns.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Create a VirusTotal Query Class
        vtq = vt_query.VTQuery()

        # See our 'Risky Domains' Notebook for the analysis and
        # statistical methods used to compute this risky set of TLDs
        risky_tlds = set(['info', 'tk', 'xyz', 'online', 'club', 'ru', 'website', 'in', 'ws',
                          'top', 'site', 'work', 'biz', 'name', 'tech', 'loan', 'win', 'pro'])

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
                if results.get('positives', 0) > 1: # At least two hits
                    print('\nRisky Domain DNS Query Found')
                    print('From: {:s} To: {:s} QType: {:s} RCode: {:s}'.format(row['id.orig_h'],
                           row['id.resp_h'], row['qtype_name'], row['rcode_name']))
                    pprint(results)
