from __future__ import absolute_import

import sys

if sys.version_info < (3,):
    ord = ord
else:
    def ord(char):
        return char
