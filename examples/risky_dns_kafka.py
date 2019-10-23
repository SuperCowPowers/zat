"""Risky DNS bat Example"""
from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint
import pickle
import json
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

# Third Party Imports
try:
    import tldextract
except ImportError:
    print('\nThis example needs tldextract. Please do a $pip install tldextract and rerun this example')
    sys.exit(1)

# Local imports
from bat import bro_log_reader
from bat.utils import vt_query, signal_utils

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
    parser.add_argument('--server', type=str, default='localhost:9092',
                        help='Specify the Kafka Server (default: localhost:9092)')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # First we create a Kafka Consumer
    kserver = args.server
    try:
        consumer = KafkaConsumer('dns', bootstrap_servers=[kserver],
                                 value_deserializer=lambda x: json.loads(x.decode('utf-8')))
    except NoBrokersAvailable:
        print('Could not connect to Kafka server: {:s}'.format(args.server))
        sys.exit(-1)

    # See if we have a serialized VirusTotal Query Class.
    # If we do not have one we'll create a new one
    try:
        vtq = pickle.load(open('vtq.pkl', 'rb'))
        print('Opening VirusTotal Query Cache (cache_size={:d})...'.format(vtq.size))
    except IOError:
        vtq = vt_query.VTQuery(max_cache_time=60*24*7) # One week cache

    # See our 'Risky Domains' Notebook for the analysis and
    # statistical methods used to compute this risky set of TLDs
    risky_tlds = set(['info', 'tk', 'xyz', 'online', 'club', 'ru', 'website', 'in', 'ws',
                      'top', 'site', 'work', 'biz', 'name', 'tech', 'loan', 'win', 'pro'])

    # Launch long lived process with signal catcher
    with signal_utils.signal_catcher(save_vtq):

        # Now lets process our Kafka 'dns' Messages
        for message in consumer:
            dns_message = message.value
        
            # Pull out the TLD
            query = dns_message['query']
            tld = tldextract.extract(query).suffix
        
            # Check if the TLD is in the risky group
            if tld in risky_tlds:
                # Make the query with the full query
                results = vtq.query_url(query)
                if results.get('positives'):
                    print('\nOMG the Network is on Fire!!!')
                    pprint(results)



        # Run the bro reader on the dns.log file looking for risky TLDs
        reader = bro_log_reader.BroLogReader(args.bro_log)
        for row in reader.readrows():

            # Pull out the TLD
            query = row['query']
            tld = tldextract.extract(query).suffix

            # Check if the TLD is in the risky group
            if tld in risky_tlds:
                # Make the query with the full query
                results = vtq.query_url(query)
                if results.get('positives', 0) > 3: # At least four hits
                    print('\nRisky Domain DNS Query Found')
                    print('From: {:s} To: {:s} QType: {:s} RCode: {:s}'.format(row['id.orig_h'],
                           row['id.resp_h'], row['qtype_name'], row['rcode_name']))
                    pprint(results)

    # Save the Virus Total Query
    save_vtq()
