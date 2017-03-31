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

# Pull in the package info
package_name = 'brothon'
package = __import__(package_name)
version = package.__version__
author = package.__author__
email = package.__email__

setup(
    name=package_name,
    version=version,
    description='Bro IDS Python Utilities',
    long_description=readme,
    author=author,
    author_email=email,
    url='https://github.com/kitware/BroThon',
    packages=[
        'brothon',
    ],
    package_dir={'brothon': 'brothon'},
    include_package_data=True,
    install_requires=[
        'watchdog'
    ],
    license='Apache',
    zip_safe=False,
    keywords='Bro IDS, Python, Networking, Security',
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
