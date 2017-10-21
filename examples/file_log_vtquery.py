"""Run a VirusTotal Query on Extracted File Hashes"""
from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Local imports
from bat import bro_log_reader
from bat.utils import vt_query

if __name__ == '__main__':
    """Run a VirusTotal Query on Extracted File Hashes"""

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('bro_log', type=str, help='Specify a bro log to run BroLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a file log
    if not args.bro_log.endswith('files.log'):
        print('This example only works with Bro files.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Create a VirusTotal Query Class
        vtq = vt_query.VTQuery()

        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)
        for row in reader.readrows():
            file_sha = row.get('sha256', '-') # Bro uses - for empty field
            if file_sha == '-':
                file_sha = row.get('sha1', '-') # Bro uses - for empthy field
                if file_sha == '-':
                    print('Should not find a sha256 or a sha1 key! Skipping...')
                    continue

            # Make the query with either sha
            results = vtq.query_file(file_sha)
            if results.get('positives', 0) > 1: # At least two hits
                pprint(results)

