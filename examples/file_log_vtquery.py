"""Run a VirusTotal Query on Extracted File Hashes"""

import os
import sys
import argparse
from pprint import pprint

# Local imports
from zat import zeek_log_reader
from zat.utils import vt_query

if __name__ == '__main__':
    """Run a VirusTotal Query on Extracted File Hashes"""

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a file log
    if 'files' not in args.zeek_log:
        print('This example only works with Zeek files.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Create a VirusTotal Query Class
        vtq = vt_query.VTQuery()

        # Run the zeek reader on a given log file
        reader = zeek_log_reader.ZeekLogReader(args.zeek_log, tail=True)
        for row in reader.readrows():
            file_sha = row.get('sha256', '-') # Zeek uses - for empty field
            if file_sha == '-':
                file_sha = row.get('sha1', '-') # Zeek uses - for empthy field
                if file_sha == '-':
                    print('Should not find a sha256 or a sha1 key! Skipping...')
                    continue

            # Make the query with either sha
            results = vtq.query_file(file_sha)
            if results.get('positives', 0) > 1: # At least two hits
                pprint(results)
