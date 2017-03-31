"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Local imports
from brothon import bro_log_reader

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

    # File may have a tilde in it
    if args.test_file:
        args.test_file = os.path.expanduser(args.test_file)

        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader(args.test_file)
        for row in reader.readrows():
            pprint(row)
