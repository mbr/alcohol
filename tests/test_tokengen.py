#!/usr/bin/env python
# coding=utf8

import time

from passlib.context import CryptContext

from alcohol.tokengen import *
from six import b

from . import BaseTestCase


class TestTokenGenerator(BaseTestCase):
    generator_class = TokenGenerator

    def setUp(self):
        # use a realistic key - previously, json.dumps choked on non-ascii
        # data
        secret_key = b('\xfa\xd2\xe7\x94\xc5\xcdF\xe5I}\xc5\x84e\x13\x91.'
                       '\xb2(\x8e\xd2\xce\xbc\xc0K\x91\x13s\xb7\xbeP\xf6'
                       '\xccgY\x04\x96\x02\x955r\x89T\xba\x08i\x87\x83?'
                       '\xdc\xc5V+\x9fl9\xe6\xb7\xc0\xecm\x08~\x1a\xaa2'
                       '\x1c\x0f!\x84\xbac}`K\x04\xd5\xe6nR\xe5\xc2,X\xff'
                       '\x0f\xf5\xb2\x1a\xeb\x9d\xc0\x19>\xc1\xdc\x11\xbfv'
                       '\xea]\xaa\xfb\x03i\x95\xe2@Q.\xe18\xe7\xe9\x84\xb3'
                       '\xf0lvEy3\xe0T\r\x97\xef\xb9wI\xd6\xc3\xc9\xd9\xb4'
                       '\x01]<a\x84\xae\xad_c\x01V\xce\xbf\xde*0:\x89q\xc9'
                       '^:Z\x08\xc8\x8a\xce\xf5\xaa\nU\xa6;\xbee\xdb\x11'
                       '\x9dh\x03\xf2\xc0\xa1\xba\x9e\xa6 2\x83\x99B;:rvF'
                       '\xa6\xc0\xcc\x133\x97\xfa\x04\x8bT{\x15m\x1c\x88x3'
                       '\x1b\x19\x1b\xa8o_\xee\x92\x1c\xd8\xd9\xf9\xb0#\\!'
                       '\xc2\xe2}Ti\xe0a\xa5\x96\xd8\xffF\x07\\\x91-|5\xad'
                       '\x0fw<\xa4y>\x08\xcd9}u\xd4\xdfT\x07\xc1cl\xf6J'
                       '\x8b\x97\x88\x9d$A\xf1\xdfs\x15\x06\xa2rG\xc9\xc1'
                       '\xb3\x86\x9f\xf2\x9a\x07!\xe4\xa7\x96\x04/\xf4\xf6'
                       '\xb1\x85\xe4b\x03\x90\xf7\xa2\xe80e\x98\xc2\xde\xc4')
        evil_key = secret_key + b('NOT')

        context = CryptContext([self.hashfunc_name])

        # less iterations so tests run quicker
        self.gen = self.generator_class(secret_key, context)
        self.evilgen = self.generator_class(evil_key, context)

    def test_simple_token(self):
        good_token = self.gen.generate_token()
        self.assertTrue(self.gen.check_token(good_token))

    def test_evil_token(self):
        evil_token = self.evilgen.generate_token()
        self.assertFalse(self.gen.check_token(evil_token))

    def test_token_bound_value(self):
        good_token = self.gen.generate_token(bound_value=b('a'))
        good_token2 = self.gen.generate_token(bound_value=b('a'))
        bad_token = self.gen.generate_token(bound_value=b('b'))

        self.assertNotEqual(good_token, good_token2)

        self.assertTrue(self.gen.check_token(good_token, bound_value=b('a')))
        self.assertTrue(self.gen.check_token(good_token2, bound_value=b('a')))
        self.assertFalse(self.gen.check_token(good_token, bound_value=b('b')))
        self.assertFalse(self.gen.check_token(good_token2, bound_value=b('b')))
        self.assertFalse(self.gen.check_token(bad_token, bound_value=b('a')))

    def test_token_unique(self):
        token1 = self.gen.generate_token()
        token2 = self.gen.generate_token()

        self.assertNotEqual(token1, token2)

    def test_single_invalid_byte_alter(self):
        token = self.gen.generate_token()
        self.assertTrue(self.gen.check_token(token))

        for i in xrange(len(token)):
            subchar = 'g'
            if token[i] == subchar:
                subchar = 'h'
            bad_token = token[:i] + subchar + token[i + 1:]

            self.assertFalse(self.gen.check_token(bad_token))

    def test_expiration(self):
        now = int(time.time())
        future = now + 3600
        far_future = future + 7200

        token = self.gen.generate_token(expires=future)
        self.assertTrue(self.gen.check_token(token, now=now))
        self.assertFalse(self.gen.check_token(token, now=future))
        self.assertFalse(self.gen.check_token(token, now=far_future))

    def test_length(self):
        self.assertLessEqual(
            len(self.gen.generate_token()),
            self.gen.token_max_length
        )

    def test_completely_broken_values(self):
        self.assertFalse(self.gen.check_token('asoihd'))
        self.assertFalse(self.gen.check_token(''))
        self.assertFalse(self.gen.check_token(False))
        self.assertFalse(self.gen.check_token(True))
        self.assertFalse(self.gen.check_token(None))
        self.assertFalse(self.gen.check_token('a' * 1024))


class TestUrlsafeTokenGenerator(TestTokenGenerator):
    generator_class = UrlsafeTokenGenerator

    def test_token_is_urlsafe(self):
        token = self.gen.generate_token()
        self.assertRegexpMatches(token, '^[a-zA-Z0-9-_]*$')

    def test_single_invalid_byte_alter(self):
        # base64 can decode to the same value for multiple hashes
        # self.skipTest('base64 encoding not injective')
        # e.g. '-g==' and '-h==' decode to the same thing
        pass
