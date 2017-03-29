"""Signal Catching utility"""
from __future__ import print_function

import signal
import sys
import time
from contextlib import contextmanager


@contextmanager
def signal_catcher(callback):
    """Catch signals and invoke the callback method"""
    def _catch_exit_signal(sig_num, _frame):
        print('Received signal {:d} invoking callback...'.format(sig_num))
        callback()

    signal.signal(signal.SIGINT, _catch_exit_signal)
    signal.signal(signal.SIGQUIT, _catch_exit_signal)
    signal.signal(signal.SIGTERM, _catch_exit_signal)
    yield


def my_exit():
    """My exit callback (just for testing)"""
    print('My Exit got called...Do some cleanup or whatever...')
    sys.exit()


def test():
    """Test the SignalCatcher"""
    with signal_catcher(my_exit):
        time.sleep(1)


if __name__ == '__main__':
    test()
