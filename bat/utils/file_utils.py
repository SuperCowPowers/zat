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


def most_recent(path, startswith=None, endswith=None):
    """Recursively inspect all files under a directory and return the most recent

        Args:
            path (str): the path of the directory to traverse
            startswith (str): the file name start with (optional)
            endswith (str): the file name ends with (optional)
        Returns:
            the most recent file within the subdirectory
    """
    candidate_files = []
    for filename in all_files_in_directory(path):
        if startswith and not os.path.basename(filename).startswith(startswith):
            continue
        if endswith and not filename.endswith(endswith):
            continue
        candidate_files.append({'name': filename, 'modtime': os.path.getmtime(filename)})

    # Return the most recent modtime
    most_recent = sorted(candidate_files, key=lambda k: k['modtime'], reverse=True)
    return most_recent[0]['name'] if most_recent else None


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

    print('Relative Dir: {:s}'.format(relative_dir(__file__, '.')))
    print('File Directory: {:s}'.format(file_dir(__file__)))
    path = file_dir(__file__)
    print('Path: {:s}'.format(path))
    for my_file in all_files_in_directory(path):
        print('\t%s' % my_file)

    print('Most Recent: {:s}'.format(most_recent(path)))
    print('Most Recent Python File: {:s}'.format(most_recent(path, endswith='.py')))

    # Test startswith
    assert most_recent(path, startswith='cache', endswith='.py') == relative_dir(__file__, 'cache.py')

    # Test when no filename match
    assert most_recent(path, endswith='.nomatch') is None


if __name__ == '__main__':
    test_utils()
