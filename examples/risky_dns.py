"""Risky DNS zat Example"""

import os
import sys
import argparse
from pprint import pprint
import pickle

# Third Party Imports
try:
    import tldextract
except ImportError:
    print('\nThis example needs tldextract. Please do a $pip install tldextract and rerun this example')
    sys.exit(1)

# Local imports
from zat import zeek_log_reader
from zat.utils import vt_query, signal_utils


def save_vtq():
    """Exit on Signal"""
    global vtq

    print('Saving VirusTotal Query Cache...')
    pickle.dump(vtq, open('vtq.pkl', 'wb'), protocol=pickle.HIGHEST_PROTOCOL)
    sys.exit()


if __name__ == '__main__':
    # Risky DNS/VT Query application
    global vtq

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a dns log
    if 'dns' not in args.zeek_log:
        print('This example only works with Zeek dns.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # See if we have a serialized VirusTotal Query Class.
        # If we do not have one we'll create a new one
        try:
            vtq = pickle.load(open('vtq.pkl', 'rb'))
            print('Opening VirusTotal Query Cache (cache_size={:d})...'.format(vtq.size))
        except IOError:
            vtq = vt_query.VTQuery(max_cache_time=60*24*7)  # One week cache

        # See our 'Risky Domains' Notebook for the analysis and
        # statistical methods used to compute this risky set of TLDs
        risky_tlds = set(['info', 'tk', 'xyz', 'online', 'club', 'ru', 'website', 'in', 'ws',
                          'top', 'site', 'work', 'biz', 'name', 'tech', 'loan', 'win', 'pro'])

        # Launch long lived process with signal catcher
        with signal_utils.signal_catcher(save_vtq):

            # Run the zeek reader on the dns.log file looking for risky TLDs
            reader = zeek_log_reader.ZeekLogReader(args.zeek_log)
            for row in reader.readrows():

                # Pull out the TLD
                query = row['query']
                tld = tldextract.extract(query).suffix

                # Check if the TLD is in the risky group
                if tld in risky_tlds:
                    # Show the risky dns
                    print('Making VT query for {:s}...'.format(query))

                    # Make the VT query
                    results = vtq.query_url(query)
                    if results.get('positives', 0) >= 1:  # At least one hit (change this higher if you want)
                        print('\nRisky Domain DNS Query Found')
                        print('From: {:s} To: {:s} QType: {:s} RCode: {:s}'.format(row['id.orig_h'],
                                                                                   row['id.resp_h'],
                                                                                   row['qtype_name'],
                                                                                   row['rcode_name']))
                        pprint(results)

        # Save the Virus Total Query
        save_vtq()
