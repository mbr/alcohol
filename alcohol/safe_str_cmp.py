#!/usr/bin/env python
# coding=utf8

from itertools import izip

# src: http://werkzeug.pocoo.org/docs/utils/#werkzeug.security.safe_str_cmp
def safe_str_cmp(a, b):
    """Compares a string in near linear time, does not end early on mismatch"""
    if len(a) != len(b):
        return False

    rv = 0
    for x, y in izip(a, b):
        rv |= ord(x) ^ ord(y)

    return rv == 0
