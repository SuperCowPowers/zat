"""Run a set of Yara Rule matches on Extracted Files"""
from __future__ import print_function
import os
import sys
import time
import argparse
from pprint import pprint

# Local imports
from brothon.utils import yara_rules, dir_watcher, signal_utils

def yara_match(file_path, rules):
    """Callback for a newly extracted file"""
    print('New Extracted File: {:s}'.format(file_path))
    print('Mathes:')
    pprint(rules.match(file_path))

def my_exit():
    """Exit on Signal"""
    print('Goodbye...')
    sys.exit()

if __name__ == '__main__':
    # Run a set of Yara Rule matches on Extracted Files

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--rule-index', type=str, help='Specify the yara rule index file (e.g. /full/path/to/yara/rules/index.yar)')
    parser.add_argument('-e', '--extract-dir', type=str, help='Specify the Bro extract_files directory (e.g. /full/path/to/bro/extract_files)')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # If no args just call help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Sanity check that the args exist and are what we expect
    if not os.path.isfile(args.rule_index):
        print('--rule-index file not found.. should be /full/path/to/yara/rules/index.yar')
        sys.exit(1)
    if not os.path.isdir(args.extract_dir):
        print('--extract-dir directory not found.. should be /full/path/to/bro/extract_files')
        sys.exit(1)

    # Create a Yara Rules Class
    print('Loading Yara Rules from {:s}'.format(args.rule_index))
    my_rules = yara_rules.YaraRules(rule_index=args.rule_index)

    # Create DirWatcher and start watching the Bro extract_files directory
    print('Watching Extract Files Directory: {:s}'.format(args.extract_dir))
    dir_watcher.DirWatcher(args.extract_dir, callback=yara_match, rules=my_rules)

    # Okay so just wait around for files to be dropped by Bro or someone hits Ctrl-C
    with signal_utils.signal_catcher(my_exit):
        while True:
            time.sleep(.5)
