"""FileTailer Python Class"""
from __future__ import print_function
import os
import sys
import argparse

# Local imports
from brothon.utils import file_tailer, signal_utils

def my_exit():
    """Exit on Signal"""
    print('Goodbye...')
    sys.exit()

if __name__ == '__main__':
    # Example to try running tailer on a file given in the args

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--bro-log', type=str, help='Specify a file to run FileTailer test on')
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
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # Run the tailer on the given file and catch any iterrupts
        with signal_utils.signal_catcher(my_exit):
            tailer = file_tailer.FileTailer(args.bro_log)
            for line in tailer.readlines():
                print(line)
