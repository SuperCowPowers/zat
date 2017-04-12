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
            rule_path (str): The path to a set of yara rules (default=None)
    """

    def __init__(self, rule_path=None):
        """YaraRules Init"""

        # Default Yara Rule Path if you want to use different set of yara rules
        #         create the class with rule_path=/full/path/to/yara/rules
        # Example:
        # $ git clone https://github.com/Yara-Rules/rules rules
        # $ yara_rules = YaraRules(rule_path=/path/to/rules)
        yara_default = file_utils.relative_dir(__file__, 'yara_rules')
        self.rule_path = rule_path or yara_default

        # Load/compile the yara rules
        self.yara_rules = yara.compile(self.rule_path)

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
    rule_path = '/home/ubuntu/data/yara_rules/index.yar'
    my_rules = YaraRules(rule_path=rule_path)
    data_path = file_utils.relative_dir(__file__, 'yara_test')
    file_path = os.path.join(data_path, 'auriga_pe_test')
    print('Matches:')
    pprint(my_rules.match(file_path))

if __name__ == "__main__":
    test()
