#!/usr/bin/env python
# coding=utf8

from binascii import hexlify, unhexlify
import json
import hashlib
import os
from struct import pack, unpack
import time

from pbkdf2 import pbkdf2_hex
from safe_str_cmp import safe_str_cmp


class TokenException(Exception):
    """Base class for token exceptions."""


class BadTokenException(TokenException):
    """The token is broken and cannot ever be a valid token."""


class InvalidTokenException(TokenException):
    """The token has a valid structure, but is invalid."""


class TokenGenerator(object):
    """Generates tokens using pbkdf2 and a secret key. Tokens can be given
       an expiration date after which they are no longer valid and be tied to a
       secret key.

       :param secret_key: The secret key used by the application. Used to
                          ensure that generated tokens stem from this
                          application.
       :param pbkdf_keylength: The length of the key to generate for use in the
                          token. This directly affects token length.
       :param pbkdf_iterations: The number of iterations that pbkdf runs.
       :param pbkdf_saltlength: The length of the salt, taken from
                          :py:func:`os.urandom`.
       :param pbkdf_hashfunc: The hash function used. Passed on to
                              :py:func:`~alcohol.pbkdf2.pbkdf2_hex`.
       """
    max_expires = 2 ** 63 - 1
    _pack_format = '!q'
    _expires_token_length = len(hexlify(pack(_pack_format, max_expires)))

    def __init__(self,
                 secret_key,
                 pbkdf_keylength=40,
                 pbkdf_iterations=1000,
                 pbkdf_saltlength=8,
                 pbkdf_hashfunc=None):
        self.secret_key = secret_key
        self.pbkdf_keylength = pbkdf_keylength
        self.pbkdf_iterations = pbkdf_iterations
        self.pbkdf_saltlength = pbkdf_saltlength
        self.hashfunc = pbkdf_hashfunc

        self._salt_token_length = 2 * pbkdf_saltlength
        self._key_token_length = 2 * pbkdf_keylength

    def _generate_key(self, salt, expires, bound_value):
        # need to use hexlify, as not all raw byte strings are
        # json dumpable
        msg = json.dumps((expires,
                          hexlify(bound_value) if bound_value else None,
                          hexlify(self.secret_key)))
        return pbkdf2_hex(msg,
                          salt,
                          self.pbkdf_iterations,
                          self.pbkdf_keylength,
                          self.hashfunc)

    def generate_token(self, expires=-1, bound_value=None):
        """Generates a new token.

        :param expires: A unix timestamp of when the token should be considered
                        expired. Must be an integer and fit into 8 bytes.
        :param bound_value: A value tied to this token. This basically acts as
                            a second token-specific secret key.
        :return: A hex string containing salt, expiry date and key combined
                into one. Its length will be
                :py:attr:`token_length` digits.
        """
        assert(self.max_expires >= expires)
        salt = hexlify(os.urandom(self.pbkdf_saltlength))
        expires_packed = hexlify(pack(self._pack_format, expires))
        key = self._generate_key(salt, expires, bound_value)
        return salt + expires_packed + key

    @property
    def token_length(self):
        """The token length.

        Contains the exact of generated tokens, in bytes. Note that tokens are
        returned as hex strings. This is the length of the returned strings."""
        return self._salt_token_length +\
               self._expires_token_length +\
               self._key_token_length

    def _unpack_token(self, token):
        if self.token_length != len(token):
            raise BadTokenException('Token has wrong length.')

        salt = token[:self._salt_token_length]
        try:
            unhexlify(salt)  # check

            expire_start = self._salt_token_length
            expire_end = self._salt_token_length + self._expires_token_length
            expires = unpack(self._pack_format,
                             unhexlify(token[expire_start:expire_end]))[0]

            key = token[-self._key_token_length:]
            unhexlify(key)
        except TypeError, e:
            raise BadTokenException(str(e))

        return salt, expires, key

    def get_expiry_time(self, token, bound_value=None):
        """Extracts the expiration time from a token.

        :param token: The token to be examined.
        :param bound_value: The same bound value that was used to generate the
                            token.
        :return: The expiration time as an integer.
        :throw TokenException: If the token is not valid other than its
                               expiration.
        """
        salt, expires, key = self._unpack_token(token)

        real_key = self._generate_key(salt, expires, bound_value)
        if not safe_str_cmp(real_key, key):
            raise InvalidTokenException('Token is invalid.')

        return expires

    def token_not_expired(self, token, bound_value=None):
        """Checks if a token is expired.

        :param token: The token to be examined.
        :param bound_value: The same bound value that was used to generate the
                            token.
        :return: True if the token is NOT expired, False if it.
        :throw TokenException: If the token is not valid other than its
                               expiration.
        """
        expiry_time = self.get_expiry_time(token, bound_value)

        # a token with an expiry time of -1 does not expire
        if -1 == expiry_time:
            return True

        if time.time() >= expiry_time:
            return False

        return True

    def check_token(self, token, bound_value=None):
        """Check a token for full validity.

        This is the function you should be using to verify tokens, most of the
        time.

        :param token: The token to be examined.
        :param bound_value: The same bound value that was used to generate the
                            token.
        :return: True if the token is valid, False if it is NOT.
        """
        try:
            return self.token_not_expired(token, bound_value)
        except TokenException:
            return False
