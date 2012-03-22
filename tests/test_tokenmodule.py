#!/usr/bin/env python
# coding=utf8

import sys

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from alcohol.tokengen import *


class TestTokenModule(unittest.TestCase):
    def setUp(self):
        # use a realistic key - previously, json.dumps choked on non-ascii
        # data
        self.secret_key = '\xfa\xd2\xe7\x94\xc5\xcdF\xe5I}\xc5\x84e\x13\x91.'\
                          '\xb2(\x8e\xd2\xce\xbc\xc0K\x91\x13s\xb7\xbeP\xf6'\
                          '\xccgY\x04\x96\x02\x955r\x89T\xba\x08i\x87\x83?'\
                          '\xdc\xc5V+\x9fl9\xe6\xb7\xc0\xecm\x08~\x1a\xaa2'\
                          '\x1c\x0f!\x84\xbac}`K\x04\xd5\xe6nR\xe5\xc2,X\xff'\
                          '\x0f\xf5\xb2\x1a\xeb\x9d\xc0\x19>\xc1\xdc\x11\xbfv'\
                          '\xea]\xaa\xfb\x03i\x95\xe2@Q.\xe18\xe7\xe9\x84\xb3'\
                          '\xf0lvEy3\xe0T\r\x97\xef\xb9wI\xd6\xc3\xc9\xd9\xb4'\
                          '\x01]<a\x84\xae\xad_c\x01V\xce\xbf\xde*0:\x89q\xc9'\
                          '^:Z\x08\xc8\x8a\xce\xf5\xaa\nU\xa6;\xbee\xdb\x11'\
                          '\x9dh\x03\xf2\xc0\xa1\xba\x9e\xa6 2\x83\x99B;:rvF'\
                          '\xa6\xc0\xcc\x133\x97\xfa\x04\x8bT{\x15m\x1c\x88x3'\
                          '\x1b\x19\x1b\xa8o_\xee\x92\x1c\xd8\xd9\xf9\xb0#\\!'\
                          '\xc2\xe2}Ti\xe0a\xa5\x96\xd8\xffF\x07\\\x91-|5\xad'\
                          '\x0fw<\xa4y>\x08\xcd9}u\xd4\xdfT\x07\xc1cl\xf6J'\
                          '\x8b\x97\x88\x9d$A\xf1\xdfs\x15\x06\xa2rG\xc9\xc1'\
                          '\xb3\x86\x9f\xf2\x9a\x07!\xe4\xa7\x96\x04/\xf4\xf6'\
                          '\xb1\x85\xe4b\x03\x90\xf7\xa2\xe80e\x98\xc2\xde\xc4'
        self.evil_key = self.secret_key + 'NOT'

        # less iterations so tests run quicker
        self.gen = TokenGenerator(self.secret_key, pbkdf_iterations=10)
        self.evilgen = TokenGenerator(self.evil_key, pbkdf_iterations=10)

    def test_simple_token(self):
        good_token = self.gen.generate_token()
        evil_token = self.evilgen.generate_token()

        with self.assertRaises(InvalidTokenException):
            self.gen.get_expiry_time(evil_token)

        with self.assertRaises(InvalidTokenException):
            self.gen.token_not_expired(evil_token)

    def test_token_bound_value(self):
        good_token = self.gen.generate_token(bound_value='a')
        good_token2 = self.gen.generate_token(bound_value='a')
        bad_token = self.gen.generate_token(bound_value='b')

        self.assertNotEqual(good_token, good_token2)

        self.assertTrue(self.gen.token_not_expired(good_token, bound_value='a'))
        self.assertTrue(self.gen.token_not_expired(good_token2, bound_value='a'))
        self.assertFalse(self.gen.check_token(good_token, bound_value='b'))
        self.assertFalse(self.gen.check_token(good_token2, bound_value='b'))
        self.assertFalse(self.gen.check_token(bad_token, bound_value='a'))

    def test_token_unique(self):
        token1 = self.gen.generate_token()
        token2 = self.gen.generate_token()

        self.assertNotEqual(token1, token2)

    def test_length_adds_up(self):
        token = self.gen.generate_token()
        self.assertEqual(len(token), self.gen.token_length)

    def test_preserves_expiration_time(self):
        expire_on = 2 ** 62
        token = self.gen.generate_token(expires=expire_on)

        self.assertEqual(self.gen.get_expiry_time(token), expire_on)

    def test_single_valid_byte_alter(self):
        token = self.gen.generate_token()

        for i in xrange(0, len(token)):
            orig_byte = token[i]
            new_byte = '0' if orig_byte != '0' else '1'
            bad_token = token[:i] + new_byte + token[i + 1:]

            with self.assertRaises(InvalidTokenException):
                self.gen.get_expiry_time(bad_token)

    def test_single_invalid_byte_alter(self):
        token = self.gen.generate_token()

        for i in xrange(8, len(token)):
            bad_token = token[:i] + 'g' + token[i + 1:]

            with self.assertRaises(BadTokenException):
                self.gen.get_expiry_time(bad_token)
