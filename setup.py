#!/usr/bin/env python
# coding=utf8

import os
import sys

from setuptools import setup, find_packages

if sys.version_info < (2, 7):
    tests_require = ['unittest2']
    test_suite = 'unittest2.collector'
else:
    tests_require = []
    test_suite = 'unittest.collector'


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(name='alcohol',
      version='0.1dev',
      description='User login signal framework.',
      long_description=read('README.rst'),
      keywords='',
      author='Marc Brinkmann',
      author_email='git@marcbrinkmann.de',
      url='http://github.com/mbr/',
      license='MIT',
      packages=find_packages(exclude=['tests']),
      tests_require=tests_require,
      test_suite='unittest2.collector',
      classifiers=[
      ]
     )
