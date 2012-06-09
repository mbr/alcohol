#!/usr/bin/env python
# coding=utf8

from datetime import datetime, timedelta
import sys
import time

from sqlalchemy import create_engine, Column, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.exc import IntegrityError

import passlib.context
from alcohol.mixins import *
from alcohol.tokengen import TokenGenerator

from . import BaseTestCase


class TestPasswordMixin(BaseTestCase):
    def setUp(self):
        class UserClass(password_mixin()):
            crypt_context = passlib.context.CryptContext(self.hashfunc_name)
            token_gen = TokenGenerator('devkey', context=crypt_context)

            def __init__(self, **kwargs):
                for k, v in kwargs.iteritems():
                    setattr(self, k, v)

        self.User = UserClass

    def test_password_check(self):
        valid_password = 's0m3p4$$w0rd'
        invalid_password = valid_password + 'x'
        user = self.User(password=valid_password)

        self.assertTrue(user.check_password(valid_password))
        self.assertFalse(user.check_password(invalid_password))

    def test_salt_passwords(self):
        user = self.User(password='a')
        user2 = self.User(password='a')

        self.assertNotEqual(user._pwhash, user2._pwhash)

    def test_password_reset_tokens_different(self):
        user = self.User(password='foo')
        token1 = user.create_reset_password_token()
        token2 = user.create_reset_password_token()

        self.assertNotEqual(token1, token2)

    def test_password_reset_token_works(self):
        user = self.User(password='foo')
        token = user.create_reset_password_token()
        self.assertTrue(user.check_password_reset_token(token))

    def test_password_reset_is_secure(self):
        user = self.User(password='foo')
        token = user.create_reset_password_token()

        for i in xrange(0, len(token)):
            orig_byte = token[i]
            new_byte = '0' if orig_byte != '0' else '1'
            bad_token = token[:i] + new_byte + token[i + 1:]

            self.assertFalse(user.check_password_reset_token(bad_token))

    def test_password_reset_expires(self):
        user = self.User(password='foo')

        start = time.time()
        token = user.create_reset_password_token(valid_for=1)
        check = user.check_password_reset_token(token)
        end = time.time()

        # still unreliable
        #if end - start >= 0.9:
        #    unittest.skip('Skipping one password check, took too long')
        #else:
        #    self.assertTrue(check)

        time.sleep(1.1)
        self.assertFalse(user.check_password_reset_token(token))

    def test_two_tokens_work_both(self):
        user = self.User(password='foo')
        token1 = user.create_reset_password_token()
        token2 = user.create_reset_password_token()

        self.assertTrue(user.check_password_reset_token(token2))
        self.assertTrue(user.check_password_reset_token(token1))
        self.assertTrue(user.check_password_reset_token(token2))

    def test_tokens_stops_working_after_pw_change(self):
        user = self.User(password='foo')
        token1 = user.create_reset_password_token()
        token2 = user.create_reset_password_token()

        user.password = 'new_password'

        self.assertFalse(user.check_password_reset_token(token2))
        self.assertFalse(user.check_password_reset_token(token1))
        self.assertFalse(user.check_password_reset_token(token2))
        self.assertFalse(user.check_password_reset_token(token1))

    def test_password_cannot_be_read(self):
        user = self.User()

        with self.assertRaises(TypeError):
            x = user.password


class TestEmailMixin(BaseTestCase):
    def setUp(self):
        class UserClass(email_mixin()):
            crypt_context = passlib.context.CryptContext(self.hashfunc_name)
            token_gen = TokenGenerator('devkey', context=crypt_context)

            def __init__(self, **kwargs):
                for k, v in kwargs.iteritems():
                    setattr(self, k, v)

        self.User = UserClass

    def test_email_verification_token_works(self):
        unverified_email = 'another@email.invalid'
        user = self.User(unverified_email=unverified_email)

        token = user.create_email_activation_token()

        self.assertTrue(user.activate_email(token))

    def test_email_verification_token_altered_fails(self):
        user = self.User(unverified_email='my@email.invalid')
        token = user.create_email_activation_token()

        for i in xrange(0, len(token)):
            orig_byte = token[i]
            new_byte = '0' if orig_byte != '0' else '1'
            bad_token = token[:i] + new_byte + token[i + 1:]

            self.assertFalse(user.activate_email(bad_token))

    def test_email_verification_token_usable_once(self):
        user = self.User(unverified_email='my@email.invalid')
        token = user.create_email_activation_token()

        self.assertTrue(user.activate_email(token))
        self.assertFalse(user.activate_email(token))

    def test_email_activation_unsets_and_sets(self):
        old_email = 'old@email.invalid'
        new_email = 'new@email.invalid'

        user = self.User(email=old_email, unverified_email=new_email)

        self.assertEqual(old_email, user.email)
        self.assertEqual(new_email, user.unverified_email)

        token = user.create_email_activation_token()

        user.activate_email(token)

        self.assertEqual(new_email, user.email)
        self.assertIsNone(user.unverified_email)

    def test_cannot_get_email_token_without_email(self):
        user = self.User()

        with self.assertRaises(AttributeError):
            user.create_email_activation_token()

    def test_can_use_any_email_token(self):
        user = self.User(unverified_email='unverified@email.invalid')

        token1 = user.create_email_activation_token()
        token2 = user.create_email_activation_token()
        token3 = user.create_email_activation_token()
        token4 = user.create_email_activation_token()
        token5 = user.create_email_activation_token()

        self.assertTrue(user.activate_email(token4))
