#!/usr/bin/env python
# coding=utf8

import base64
from binascii import hexlify, unhexlify
import hashlib
import json
import math
import os
import struct
import time

import passlib.context


# lifted from itsdangerous
# https://github.com/mitsuhiko/itsdangerous/blob/master/itsdangerous.py
def base64_encode(s):
    return base64.urlsafe_b64encode(s).strip('=')


def base64_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


class TokenException(Exception):
    """Base class for token exceptions."""


class TokenGenerator(object):
    """Generates tokens using a :py:class:`~passlib.context.CryptContext` and a
    secret key. Tokens can be given an expiration date after which they are no
    longer valid as well.

    Note that the first handler from the context is used with its default
    settings. Also, tokens contain no parameters of the handler other than the
    salt - this means that changes in the context can invalidate all previously
    issued tokens.

    Hashing handlers that depend on non-fixed settings other than salt are not
    supported and must implement the optional
    :py:attr:`~passlib.utils.handlers.GenericHandler.checksum_size`.

    Tokens generally are of the structure 'SaltExpiresHash' where 'Salt' is the
    salt, 'Expires' a base64 encoded packed integer containing the expiry
    timestamp (12 bytes long) and 'Hash' the resulting hash.

    :param secret_key: The secret key used by the application. Used to ensure
    that generated tokens stem from this application.

    :param context: A :py:class:`passlib.context.CryptContext`.
    """
    max_expires = 2 ** 63 - 1
    _pack_format = '!q'
    _expires_token_length = len(struct.pack(_pack_format, 0))

    DEFAULT_SCHEME = 'pbkdf2_sha256'

    def __init__(self, secret_key, context=None):
        if not context:
            context = passlib.context.CryptContext(
                schemes=[self.DEFAULT_SCHEME]
            )

        self.secret_key = secret_key
        self.handler_class = context.handler()

    def _generate_hash(self, handler, expires, bound_value):
        # need to use hexlify, as not all raw byte strings are
        # json dumpable
        msg = json.dumps((expires,
                          hexlify(bound_value) if bound_value else None,
                          hexlify(self.secret_key)))

        return handler._calc_checksum(msg)

    def generate_token(self, expires=-1, bound_value=None):
        """Generates a new token.

        :param expires: A unix timestamp of when the token should be considered
                        expired. Must be an integer and fit into 8 bytes.
        :param bound_value: A value tied to this token. This basically acts as
                            a second token-specific secret key.
        :return: A base64 string containing salt, expiry date and key combined
                into one. Its length will be :py:attr:`token_length` characters
                long.
        """
        assert(self.max_expires >= expires)
        expires = int(expires)

        # generate new salt
        handler = self.handler_class(salt=None, use_defaults=True)

        expires_packed = struct.pack(self._pack_format, expires)
        hash = self._generate_hash(handler, expires, bound_value)

        return str(handler.salt) + expires_packed + str(hash)

    @property
    def token_max_length(self):
        """The token length.

        Contains the exact of generated tokens, in bytes. This is the length of
        the returned token strings."""
        return self.handler_class.default_salt_size +\
               self._expires_token_length +\
               self.handler_class.checksum_size

    def _unpack_token(self, token):
        token = str(token)

        salt = token[:self.handler_class.default_salt_size]

        expire_start = self.handler_class.default_salt_size
        expire_end = expire_start + self._expires_token_length

        expire_packed = token[expire_start:expire_end]

        expires = struct.unpack(self._pack_format, expire_packed)[0]

        hash = token[expire_end:]

        return salt, expires, hash

    def check_token(self, token, bound_value=None, now=None):
        """Check a token for full validity.

        :param token: The token to be examined.
        :param bound_value: The same bound value that was used to generate the
                            token.
        :return: True if the token is valid, False if it is NOT.
        """

        if not now:
            now = int(time.time())

        try:
            salt, expires, hash = self._unpack_token(token)
        except (ValueError, TypeError, TokenException, struct.error):
            return False

        try:
            handler = self.handler_class(salt=salt, use_defaults=True)
        except (UnicodeDecodeError, ValueError):
            # happens when trying to decode garbage salt
            return False

        correct_hash = str(self._generate_hash(handler, expires, bound_value))

        # check if hash is correct
        if not hash == correct_hash:
            return False

        # check if token hasn't expired
        if -1 != expires and not now < expires:
            return False

        return True


def _base64_size(n):
    return int(math.ceil(n * 8 / 24.0)) * (24 / 6)


class UrlsafeTokenGenerator(TokenGenerator):
    @property
    def token_max_length(self):
        return _base64_size(
            super(UrlsafeTokenGenerator, self).token_max_length
        )

    def generate_token(self, *args, **kwargs):
        t = super(UrlsafeTokenGenerator, self).generate_token(
            *args, **kwargs
        )
        return base64_encode(t)

    def check_token(self, token, *args, **kwargs):
        try:
            raw_token = base64_decode(str(token))
        except TypeError:
            return False

        return super(UrlsafeTokenGenerator, self).check_token(
            raw_token, *args, **kwargs
        )
