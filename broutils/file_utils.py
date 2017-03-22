"""File utilities that might be useful"""
from __future__ import print_function
import os


def all_files_in_directory(path):
    """Recursively list all files under a directory

        Args:
            path: the path of the directory to traverse
        Returns:
            a list of all the files contained withint the directory
    """
    file_list = []
    for dirname, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            # Skip OS Files
            if filename != '.DS_Store':
                file_list.append(os.path.join(dirname, filename))
    return file_list


def file_dir(file_path):
    """Root directory for a file_path

        Args:
            file_path: a fully qualified file path
        Returns:
            the directory which contains the file
    """
    return os.path.dirname(os.path.realpath(file_path))


def relative_dir(file_path, rel_dir):
    """Relative directory to the file_path

        Args:
            file_path: a fully qualified file path
        Returns:
            the relative directory
    """
    return os.path.join(file_dir(file_path), rel_dir)


def test_utils():
    """Test the utility methods"""

    path = relative_dir(__file__, '.')
    print('Path: %s' % path)
    for my_file in all_files_in_directory(path):
        print('\t%s' % my_file)


if __name__ == '__main__':
    test_utils()
