#!/usr/bin/env python

import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

readme = open('README.rst').read()
doclink = """
Documentation
-------------

The full documentation is at http://broutils.rtfd.org."""
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

setup(
    name='broutils',
    version='0.1.2',
    description='Bro IDS Python Utilities',
    long_description=readme + '\n\n' + doclink + '\n\n' + history,
    author='Brian Wylie',
    author_email='brian.wylie@kitware.com',
    url='https://github.com/kitware/broutils',
    packages=[
        'broutils',
    ],
    package_dir={'broutils': 'broutils'},
    include_package_data=True,
    install_requires=[
    ],
    license='Apache',
    zip_safe=False,
    keywords='broutils',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy'
    ],
)
