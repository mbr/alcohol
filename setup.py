#!/usr/bin/env python
# coding=utf8

import os

from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(name='alcohol',
      version='0.4',
      description='Handles user authentication, in a way.',
      long_description=read('README.rst'),
      author='Marc Brinkmann',
      author_email='git@marcbrinkmann.de',
      url='http://github.com/mbr/alcohol',
      license='MIT',
      packages=find_packages(exclude=['tests']),
      install_requires=['blinker', 'passlib>=1.6', 'six', 'itsdangerous>=0.14'],
)
