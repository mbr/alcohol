#!/usr/bin/env python
# coding=utf8

from binascii import hexlify
from datetime import datetime
import hashlib
import os
import time

from pbkdf2 import pbkdf2_hex
from safe_str_cmp import safe_str_cmp

from sqlalchemy import Column, String, DateTime, func

from alcohol.tokengen import TokenGenerator


def password_mixin(get_token_generator_func=lambda obj: obj.token_gen,
                   pbkdf_keylength=40,
                   pbkdf_saltlength=8,
                   pbkdf_iterations=10000,
                   pbkdf_hashfunc=None):
    """Create a new :py:class:`~alcohol.mixins.PasswordMixin` class.

    :param get_token_generator_func: A function that given an object returns a
                                     token generator instance. Defaults to the
                                     equivalent of `getattr(obj, 'token_gen')`.
    :param pbkdf_keylength: Length of key to be generated from the users
                            password.
    :param pbkdf_saltlength: Length of the salt used, taken from os.urandom.
    :param pbkdf_iterations: The number of pbkdf2 iterations to use.
    :param pbkdf_hashfunc: The hash function used. Passed on to
                           :py:func:`~alcohol.pbkdf2.pbkdf2_hex`.
    :return: A class suitable for mixing into any SQLAlchemy model object.
    """
    class PasswordMixin(object):
        # hexlify doubles size of input!
        _pw_key = Column(String(pbkdf_keylength * 2))
        _pw_salt = Column(String(pbkdf_saltlength * 2))

        def _hash_pw(self, salt, pw):
            key = pbkdf2_hex(pw.encode('utf-8'),
                             salt,  # use as is, same entropy as unhexlified
                             pbkdf_iterations,
                             pbkdf_keylength,
                             pbkdf_hashfunc
                             )
            return key

        def check_password(self, password):
            return safe_str_cmp(
                self._hash_pw(self._pw_salt, password),
                self._pw_key
            )

        def check_password_reset_token(self, token):
            return get_token_generator_func(self).check_token(token,
                                                              self._pw_key)

        def create_reset_password_token(self, valid_for=60 * 60 * 24):
            valid_until = int(time.time() + valid_for)
            return \
                get_token_generator_func(self).generate_token(valid_until,
                                                          self._pw_key)

        @property
        def password(self):
            raise TypeError(
                'password property is write-only, use check_password'
            )

        @password.setter
        def password(self, new_password):
            self._pw_salt = hexlify(
                os.urandom(pbkdf_saltlength)
            )
            self._pw_key = self._hash_pw(self._pw_salt, new_password)

    return PasswordMixin


def email_mixin(get_token_generator_func=lambda obj: obj.token_gen,
                max_email_length=512, email_unique=False):
    """Create a new :py:class:`alcohol.mixins.EmailMixin` class.

    :param get_token_generator_func: A function that given an object returns a
                                     token generator instance. Defaults to the
                                     equivalent of `getattr(obj, 'token_gen')`.
    :param max_email_length: The maximum allowed length for an email.
    :param email_unique: Whether or not to add a UNIQUE-constraint on the email
                         column.
    :return: A class suitable for mixing into any SQLAlchemy model object.
    """
    class EmailMixin(object):
        email = Column(String(max_email_length),
                       index=True,
                       unique=email_unique)
        unverified_email = Column(String(max_email_length))

        def activate_email(self, token):
            if not get_token_generator_func(self).check_token(
                token, self.unverified_email):
                return False

            self.email = self.unverified_email
            self.unverified_email = None
            return True

        def create_email_activation_token(self, valid_for=60 * 60 * 24):
            if not self.unverified_email:
                raise TypeError('No email set or email already verified')
            valid_until = int(time.time() + valid_for)
            return \
                get_token_generator_func(self).generate_token(valid_until,
                                                     self.unverified_email)

    return EmailMixin


def timestamp_mixin(use_serverside_now=True):
    """Create a new :py:class:`alcohol.mixins.TimestampMixin` class.

    :param use_serverside_now: Whether to use an SQL NOW() function or add a
                               client-side default-value of
                               :py:attr:`datetime.datetime.now`.
    :return: A class suitable for mixing into any SQLAlchemy model object.
    """
    if use_serverside_now:
        class TimestampMixin(object):
            created = Column(DateTime, default=datetime.utcnow, nullable=False)
            modified = Column(DateTime, onupdate=datetime.utcnow)
    else:
        class TimestampMixin(object):
            created = Column(DateTime, server_default=func.now(),
                             nullable=False)
            modified = Column(DateTime, onupdate=func.now())

    return TimestampMixin
