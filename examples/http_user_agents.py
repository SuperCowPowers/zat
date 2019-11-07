"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse
from collections import Counter
from pprint import pprint

# Local imports
from zat import bro_log_reader

if __name__ == '__main__':
    # Example to run the bro log reader on a given file

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('bro_log', type=str, help='Specify a bro log to run BroLogReader test on')
    parser.add_argument('-t', action='store_true', default=False, help='Sets the program to tail a live Zeek log')
    parser.add_argument('-s', action='store_true', default=False, help='Only print the summary of the findings.')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a http log
    if 'http' not in args.bro_log:
        print('This example only works with Zeek http.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Run the bro reader on a given log file counting up user agents
        http_agents = Counter()
        reader = bro_log_reader.BroLogReader(args.bro_log, tail=args.t)
        for count, row in enumerate(reader.readrows()):
            # Track count
            http_agents[row['user_agent']] += 1

            # Every hundred rows report agent counts (least common)
            if not args.s:
                if count%100==0:
                    print('\n<<<Least Common User Agents>>>')
                    pprint(http_agents.most_common()[:-50:-1])

        # Also report at the end (if there is one)
        print('\nLeast Common User Agents:')
        pprint(http_agents.most_common()[:-50:-1])
