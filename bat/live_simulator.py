"""LiveSimulator: This class reads in various Bro logs. The class utilizes
                 the BroLogReader and simply loops over the static bro log
                 file, replaying rows and changing any time stamps
        Args:
            eps (int): Events Per Second that the simulator will emit events (default = 10)
            max_rows (int): The maximum number of rows to generate (default = None (go forever))
"""
from __future__ import print_function
import os
import time
import datetime
import itertools

# Third party
import numpy as np

# Local Imports
from bat import bro_log_reader
from bat.utils import file_utils


class LiveSimulator(object):
    """LiveSimulator: This class reads in various Bro logs. The class utilizes the
                      BroLogReader and simply loops over the static bro log file
                      replaying rows at the specified EPS and changing timestamps to 'now()'
    """

    def __init__(self, filepath, eps=10, max_rows=None):
        """Initialization for the LiveSimulator Class
           Args:
               eps (int): Events Per Second that the simulator will emit events (default = 10)
               max_rows (int): The maximum number of rows to generate (default = None (go forever))
        """

        # Compute EPS timer
        # Logic:
        #     - Normal distribution centered around 1.0/eps
        #     - Make sure never less than 0
        #     - Precompute 1000 deltas and then just cycle around
        self.eps_timer = itertools.cycle([max(0, delta) for delta in np.random.normal(1.0/float(eps), .5/float(eps), size=1000)])

        # Initialize the Bro log reader
        self.log_reader = bro_log_reader.BroLogReader(filepath, tail=False)

        # Store max_rows
        self.max_rows = max_rows

    def readrows(self):
        """Using the BroLogReader this method yields each row of the log file
           replacing timestamps, looping and emitting rows based on EPS rate
        """

        # Loop forever or until max_rows is reached
        num_rows = 0
        while True:

            # Yield the rows from the internal reader
            for row in self.log_reader.readrows():
                yield self.replace_timestamp(row)

                # Sleep and count rows
                time.sleep(next(self.eps_timer))
                num_rows += 1

                # Check for max_rows
                if self.max_rows and (num_rows >= self.max_rows):
                    return

    @staticmethod
    def replace_timestamp(row):
        """Replace the timestamp with now()"""
        if 'ts' in row:
            row['ts'] = datetime.datetime.utcnow()
        return row


def test():
    """Test for LiveSimulator Python Class"""

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    test_path = os.path.join(data_path, 'conn.log')
    print('Opening Data File: {:s}'.format(test_path))

    # Create a LiveSimulator reader
    reader = LiveSimulator(test_path, max_rows=10)
    for line in reader.readrows():
        print(line)
    print('Read with max_rows Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
