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

        # Load the yara rules
        self.yara_rules = self.get_rules_from_disk(self.rule_path)

    def match(self, file_path):
        """Match the existing set of yara rules against the file
            Args:
               file_path (str): The /full/path/to/the/file to be matched against
        """

        # Sanity check file path
        if not os.path.isfile(file_path):
            raise RuntimeError('Could not find file: %s' % file_path)

        # Get Matches
        matches = self.yara_rules.match_path(file_path)

        # The matches data is organized in the following way
        # {'filename1': [match_list], 'filename2': [match_list]}
        # match_list = list of match
        # match = {'meta':{'description':'blah}, tags=[], matches:True,
        #           strings:[string_list]}
        # string = {'flags':blah, 'identifier':'$', 'data': FindWindow, 'offset'}
        #
        # So we're going to flatten a bit
        # {filename_match_meta_description: string_list}
        flat_data = collections.defaultdict(list)
        for filename, match_list in matches.items():
            for match in match_list:
                if 'description' in match['meta']:
                    new_tag = filename+'_'+match['meta']['description']
                else:
                    new_tag = filename+'_'+match['rule']
                for match in match['strings']:
                    flat_data[new_tag].append(match['data'])
                # Remove duplicates
                flat_data[new_tag] = list(set(flat_data[new_tag]))

        return {'matches': flat_data}

    # We want to load this once per module load
    @staticmethod
    def get_rules_from_disk(yara_rule_path):
        ''' Recursively traverse the yara/rules directory for rules '''

        # Try to find the yara rules directory
        if not os.path.isdir(yara_rule_path):
            raise RuntimeError('Could not find yara rules directory: %s' % yara_rule_path)

        # Okay load in all the rules under the yara rule path
        rules = yara.load_rules(rules_rootpath=yara_rule_path, fast_match=True)

        return rules


# Unit test: Create the class and test it
def test():
    """yara_rules.py test"""
    from pprint import pprint

    # Create and invoke the class
    my_rules = YaraRules()
    data_path = file_utils.relative_dir(__file__, 'yara_test')
    file_path = os.path.join(data_path, 'auriga_pe_test')
    print('Mathes:')
    pprint(my_rules.match(file_path))

if __name__ == "__main__":
    test()
