"""DirWatcher: Watches a directory and calls the callback when files are created"""

import os
import time

# Other Imports
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Local Imports
from bat.utils import file_utils


class DirWatcher(FileSystemEventHandler):
    """Watches a directory and calls the callback when files are created/modified"""

    def __init__(self, data_dir, callback, **kwargs):
        """Initialization"""
        self.callback = callback
        self.kwargs = kwargs

        # Now setup dynamic monitoring of the data directory
        observer = Observer()
        observer.schedule(self, path=data_dir)
        observer.start()

    def on_any_event(self, event):
        """File created or modified"""
        if os.path.isfile(event.src_path):
            self.callback(event.src_path, **self.kwargs)


def my_callback(file_path):
    """Callback for new file"""
    print('New File Created: {:s}'.format(file_path))


def test():
    """Test the DirWatcher Class"""
    watch_path = file_utils.relative_dir(__file__, '../../data')
    print('Watching Directory: %s' % watch_path)
    DirWatcher(watch_path, my_callback)

    # Create a file and then delete it
    temp_file = os.path.join(watch_path, 'test.tmp')
    open(temp_file, 'w').close()
    time.sleep(1)
    os.remove(temp_file)


if __name__ == '__main__':
    test()
