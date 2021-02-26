"""Cert Checker zat Example"""

import os
import sys
import argparse
from pprint import pprint

# Local imports
from zat import zeek_log_reader
from zat.utils import vt_query

if __name__ == '__main__':
    # Example to check all the x509 Certs from 'Let's Encrypt' for potential phishing/malicious sites

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a dns log
    if 'x509' not in args.zeek_log:
        print('This example only works with Zeek x509.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Create a VirusTotal Query Class
        vtq = vt_query.VTQuery()

        # These domains may be spoofed with a certificate issued by 'Let's Encrypt'
        spoofed_domains = set(['paypal', 'gmail', 'google', 'apple','ebay', 'amazon'])

        # Run the zeek reader on the x509.log file looking for spoofed domains
        reader = zeek_log_reader.ZeekLogReader(args.zeek_log, tail=True)
        for row in reader.readrows():

            # Pull out the Certificate Issuer
            issuer = row['certificate.issuer']
            if "Let's Encrypt" in issuer:

                # Check if the certificate subject has any spoofed domains
                subject = row['certificate.subject']
                if any([domain in subject for domain in spoofed_domains]):
                    print('\n<<< Suspicious Certificate Found >>>')
                    pprint(row)

                    # Make a Virus Total query with the spoofed domain (just for fun)
                    query_domain = subject[3:] # Just chopping off the 'CN=' part
                    results = vtq.query_url(query_domain)
                    if results.get('positives', 0) >= 2: # At least two hits
                        print('\n<<< Virus Total Query >>>')
                        pprint(results)
