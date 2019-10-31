"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Local imports
from bat import bro_log_reader

if __name__ == '__main__':
    # Example to run the bro log reader on a given file

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('bro_log', type=str, help='Specify a bro log to run BroLogReader test on')
    parser.add_argument('-t', '--tail', action='store_true', help='Turn on log tailing')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=args.tail, strict=True)
        for row in reader.readrows():
            pprint(row)
