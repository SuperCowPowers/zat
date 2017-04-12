"""YaraRules Class"""

from __future__ import print_function
import os
import collections

# Third party
import yara

# Local Imports
from brothon.utils import file_utils


class YaraRules(object):
    """YaraRules: Will run a set of Yara Rules against a file.

        Args:
            rule_index (str): The path to a set of yara rule index file
    """

    def __init__(self, rule_index):
        """YaraRules Init
           Note: Download yara rules from their repo and give index file
           $ git clone https://github.com/Yara-Rules/rules rules
           $ yara_rules = YaraRules(rule_index=/path/to/rules/index.yar)
        """

        # Sanity check fule index
        if not os.path.isfile(rule_index):
            raise RuntimeError('Could not find file: %s' % rule_index)

        # Load/compile the yara rules
        self.yara_rules = yara.compile(rule_index)

    def match(self, file_path):
        """Match the existing set of yara rules against the file
            Args:
               file_path (str): The /full/path/to/the/file to be matched against
        """

        # Sanity check file path
        if not os.path.isfile(file_path):
            raise RuntimeError('Could not find file: %s' % file_path)

        # Get Matches
        return self.yara_rules.match(file_path)


# Unit test: Create the class and test it
def test():
    """yara_rules.py test"""
    from pprint import pprint

    # Create and invoke the class
    rule_index = file_utils.relative_dir(__file__, 'yara_test/index.yar')
    my_rules = YaraRules(rule_index=rule_index)
    data_path = file_utils.relative_dir(__file__, 'yara_test')
    file_path = os.path.join(data_path, 'auriga_pe_test')
    print('Matches:')
    pprint(my_rules.match(file_path))

if __name__ == "__main__":
    test()
