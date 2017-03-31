"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Local imports
from brothon import bro_log_reader
from brothon.utils import vt_query

if __name__ == '__main__':
    # Example to run the bro log reader on a given file

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--test-file', type=str, help='Specify a bro log to run BroLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # If no args just call help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Sanity check that this is a file log
    if not args.test_file.endswith('files.log'):
        print('This example only works with Bro files.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.test_file:
        args.test_file = os.path.expanduser(args.test_file)

        # Create a VirusTotal Query Class
        vtq = vt_query.VTQuery()

        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader(args.test_file, tail=True)
        for row in reader.readrows():
            file_sha = row.get('sha256', '-') # Bro uses - for empty field
            if file_sha == '-':
                file_sha = row.get('sha1', '-') # Bro uses - for empthy field
                if file_sha == '-':
                    print('Should not find a sha256 or a sha1 key! Skipping...')
                    continue

            # Make the query with either sha
            pprint(vtq.query(file_sha))
