#!/usr/bin/env python
# coding=utf8

import os
import sys

from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(name='alcohol',
      version='0.2.1',
      description='User login signal framework, also includes pbkdf2, token'\
      'generation and SQLAlchemy user mixins.',
      long_description=read('README.rst'),
      keywords='user,users,login,pbkdf2,sqlalchemy,tokens',
      author='Marc Brinkmann',
      author_email='git@marcbrinkmann.de',
      url='http://github.com/mbr/',
      license='MIT',
      packages=find_packages(exclude=['tests']),
      install_requires=['blinker'],
      classifiers=[
      ]
     )
